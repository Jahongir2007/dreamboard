const express = require('express');
const AuthVerify = require('auth-verify');
const bodyParser = require('body-parser');
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const { Server } = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
app.set("view engine", "ejs");
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set("views", path.join(__dirname, "views"));

// --- Initialize SQLite Database ---
const db = new sqlite3.Database("./dreamboard.db", (err) => {
  if (err) console.error("❌ DB connection failed:", err);
  else console.log("✅ Connected to SQLite database.");
});

// --- Create Users Table if not exists ---
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    username TEXT UNIQUE,
    password TEXT,
    verified INTEGER DEFAULT 0
  );
`);

// --- Create Dreams Table if not exists ---
db.run(`
  CREATE TABLE IF NOT EXISTS dreams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    dream TEXT NOT NULL,
    likes INTEGER DEFAULT 0,
    views INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// --- Create Likes Table if not exists ---
db.run(`
    CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email INTEGER NOT NULL,
    dream_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_email, dream_id)
);
`);

db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_likes_user_dream ON likes(user_email, dream_id)`);

// --- Create Notifications Table if not exists ---
db.run(`
    CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_email TEXT,          -- who receives the notification
  message TEXT,             -- notification text
  is_read INTEGER DEFAULT 0, -- 0 = unread, 1 = read
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`);

const auth = new AuthVerify({jwtSecret: 'DB_SECRET', storeTokens: 'memory', otpExpiry: '5m'});

const onlineUsers = new Map();
global.io = io;
global.onlineUsers = onlineUsers;

// --- SOCKET EVENTS ---
io.on("connection", (socket) => {
  console.log("🟢 Connected:", socket.id);

  // Identify user after login
  socket.on("identify", (email) => {
    onlineUsers.set(email, socket.id);
    console.log(`📧 ${email} is online`);
  });

  // Disconnect
  socket.on("disconnect", () => {
    for (let [email, id] of onlineUsers.entries()) {
      if (id === socket.id) onlineUsers.delete(email);
    }
    console.log("🔴 Disconnected:", socket.id);
  });
});

auth.otp.setSender({
    via: 'email',
    sender: 'jahongir.nodirovich.2007@gmail.com',
    pass: "hwsx tnna akqc ftot",
    service: 'gmail'
});

auth.otp.maxAttempt(50);

app.get('/', async (req, res)=> {
    try{
        const user = await auth.jwt.verify(req); // returns object, not string
        return res.render('feed', { username: user.username, email: user.email });    
    }catch(err){
        return res.render('index');
    }
});
app.get('/signup', (req, res)=> res.render('signup'));
app.get('/login', (req, res)=> res.render('login'));
app.use(express.static("public"));
app.get('/verify-info', async (req, res)=>{
    const email = req.query.email || "";
    res.render("verify-info", {email});
});

app.post('/signup', (req, res)=>{
    const {email, password, username} = req.body;

    if(!email || !password || !username) return res.json({ success: false, message: "Please fill in all fields" });

    db.get(`SELECT * FROM users WHERE email = ? AND username = ?`, [email, username], (err, row)=>{
        if(err){
            console.error("DB Error:", err)
        } else if (row){
            return res.json({ success: false, message: `You've already created your account you should <a href="/login" class="link-text">Log In</a>`});
        }else{
            // return res.json({success: true, message: "Email acceptable!"});
            auth.otp.generate(6).set(email, (err)=>{
                if(err) throw err;

                auth.otp.message({
                    to: email,
                    subject: "Email verification for Dreamboard",
                    html: `<center><h4>Email verification for Dreamboard</h4></center>
                    <p>Dear ${username} your code is <b>${auth.otp.code}</b></p>`
                }, (err, info)=>{
                    if(err) console.log('Error in sending: ', err);
                    else console.log('sent', info && info.messageId);
                    return res.json({ success: true, message: `We've sent you verification code to your email`});
                });
            });

            // Hash password
            const saltRounds = 10; // higher = more secure, slower
            bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
            if (err) return console.error(err);

                db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, [username, email, hashedPassword], function(err) {
                    if (err) {
                    console.error("Error inserting user:", err.message);
                    } else {
                    console.log(`User inserted with ID ${this.lastID}`);
                    }
                });
            });
        } 
    });
});

app.post('/verify-email', (req, res)=>{
    const {email, otp} = req.body;
    console.log(email, otp);
    auth.otp.verify({check: email, code: otp }, (err, isValid)=>{
        if(err) console.log(err);
        if(isValid){
            db.run(`UPDATE users SET verified = 1 WHERE email = ?`, [email], (err)=>{
                if (err) return res.status(500).json({ success: false, message: `DB error: ${err}` });
                db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err1, row)=>{
                    if(err1) return res.status(500).json({ success: false, message: `DB error: ${err1}` });
                    await auth.jwt.sign({ email, username: row.username, role: 'user' }, '240h', { res });
                
                    return res.json({success: true, message: "Your email verified!"});
                });
            });
        }else{
            return res.json({success: false, message: "Verification code is incorrect"});
        }
    });
});

app.get('/feed', async (req, res) => {
  try {
    const user = await auth.jwt.verify(req); // returns object, not string
    db.all(`
    SELECT d.*, 
      CASE WHEN l.id IS NOT NULL THEN 1 ELSE 0 END AS liked
    FROM dreams d
    LEFT JOIN likes l ON d.id = l.dream_id AND l.user_email = ?
    ORDER BY d.id DESC
  `, [user.email], (err, dreams) => {
    if (err) return res.status(500).send("DB Error");
    return res.render('feed', { username: user.username, email: user.email, dreams});
  });

    // return res.render('feed', { username: user.username, email: user.email });
  } catch (err) {
    console.log('JWT verification failed:', err.message);
    return res.redirect('/login'); // redirect if invalid token
  }
});

app.post('/login', (req, res)=>{
    const {usernameOrEmail, password} = req.body;
    console.log(usernameOrEmail, password);
    db.get(`SELECT * FROM users WHERE (email = ? OR username = ?)`, [usernameOrEmail, usernameOrEmail], async (err, user) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "DB error" });
        }

        if (!user) {
            return res.status(401).json({ success: false, message: "Email/username or password is incorrect" });
        }

        try {
        // Compare password securely with bcrypt
        console.log(user);
        const match = await bcrypt.compare(password, user.password);
        if (!match)
            return res.status(401).json({ success: false, message: "Email/username or password is incorrect" });

        // Optional email verification
        if (user.verified !== 1) {
            return res.status(403).json({ success: false, message: "Please verify your email first." });
        }

        await auth.jwt.sign({ username: user.username, email: user.email, role: 'user' }, '240h', { res });
        return res.json({ success: true, message: "Welcome to feed page" });
        } catch (e) {
        console.error("bcrypt error:", e);
        return res.status(500).json({ success: false, message: "Server error." });
        }
    });
});

app.get('/add-dream', async (req, res)=>{
    try{
        const user = await auth.jwt.verify(req);
        console.log(user.username, user.email);
        return res.render('add-dream', {username: user.username, email: user.email});
    }catch(err){
        console.log('JWT verification failed:', err.message);
        return res.render('login'); // redirect if invalid token
    }
});

app.post('/add-dream', async (req, res)=>{
  try{
    await auth.jwt.verify(req);
    const {author, dream} = req.body;
    console.log(author, dream);

    db.run(`INSERT INTO dreams (author, dream) VALUES (?, ?)`, [author, dream], (err)=>{
        if (err) {
            console.error('DB insert error:', err);
            return res.status(500).json({ success: false });
        }
        const msg = `🌟 New dream posted!`;
  
        // Save notification for all users (optional: except the author)
        db.run(`INSERT INTO notifications (user_email, message) VALUES (?, ?)`, ["ALL", msg]);

        io.emit("newDream", msg); // notify all users

        return res.json({ success: true, message: "Dream added!" });
    });
  }catch(err){
    console.log(err);
    return res.render('login');
  }
});

app.post('/dream/view/:id', (req, res) => {
  const dreamId = parseInt(req.params.id);
  if (isNaN(dreamId)) {
    return res.status(400).json({ success: false, message: "Invalid dream ID" });
  }

  db.run(`UPDATE dreams SET views = views + 1 WHERE id = ?`, [dreamId], function (err) {
    if (err) {
      return res.status(500).json({ success: false, message: err.message });
    }

    if (this.changes === 0) {
      return res.status(404).json({ success: false, message: "Dream not found" });
    }

    return res.status(200).json({ success: true });
  });
});

app.post('/dream/like/:id', async (req, res) => {
  try {
    const user = await auth.jwt.verify(req);
    const dreamId = parseInt(req.params.id);
    if (isNaN(dreamId)) {
      return res.status(400).json({ success: false, message: "Invalid dream ID" });
    }

    db.get(`SELECT * FROM likes WHERE user_email = ? AND dream_id = ?`, [user.email, dreamId], (err, isLiked) => {
      if (err) return res.status(500).json({ success: false, message: err.message });

      if (isLiked) {
        // Unlike
        db.run(`DELETE FROM likes WHERE user_email = ? AND dream_id = ?`, [user.email, dreamId], (errUnlike) => {
          if (errUnlike) return res.status(500).json({ success: false, message: errUnlike.message });

          db.run(`UPDATE dreams SET likes = CASE WHEN likes > 0 THEN likes - 1 ELSE 0 END WHERE id = ?`, [dreamId], (errSubLike) => {
            if (errSubLike) return res.status(500).json({ success: false, message: errSubLike.message });

            db.get(`SELECT likes FROM dreams WHERE id = ?`, [dreamId], (err, row) => {
              if (err) return res.status(500).json({ success: false, message: err.message });
              return res.json({ success: true, liked: false, likes: row.likes });
            });
          });
        });
      } else {
        // Like
        db.run(`INSERT INTO likes (user_email, dream_id) VALUES (?, ?)`, [user.email, dreamId], (errInsLike) => {
          if (errInsLike) return res.status(500).json({ success: false, message: errInsLike.message });

          db.run(`UPDATE dreams SET likes = likes + 1 WHERE id = ?`, [dreamId], (errAddLike) => {
            if (errAddLike) return res.status(500).json({ success: false, message: errAddLike.message });

            db.get(`SELECT author, likes FROM dreams WHERE id = ?`, [dreamId], (errNotif, dream) => {
              if (errNotif) return res.status(500).json({ success: false, message: errNotif.message });

              // 🔔 Send notification only if liker ≠ author
              if (dream && dream.author !== user.email) {
                const msg = `💖 Your dream got a new like!`;

                db.run(`INSERT INTO notifications (user_email, message) VALUES (?, ?)`, [dream.author, msg]);

                const authorSocket = onlineUsers.get(dream.author);
                if (authorSocket) {
                  io.to(authorSocket).emit("likeNotification", msg);
                }
              }

              return res.json({ success: true, liked: true, likes: dream.likes });
            });
          });
        });
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/notifications/count", async (req, res) => {
  const user = await auth.jwt.verify(req);
  db.get(`SELECT COUNT(*) as count FROM notifications WHERE user_email = ? AND is_read = 0`, [user.email],
    (err, row) => {
      if (err) return res.json({ count: 0 });
      res.json({ count: row.count });
    }
  );
});

app.get('/dreams', async (req, res)=>{
  try{
    const user = await auth.jwt.verify(req);
    console.log(user.email);
    db.all(`SELECT * FROM dreams WHERE author = ?`, [user.email], (err, dreams)=>{
      if(err) return res.status(500).json({success: false, message: err.message});
      
      return res.render('dreams', {user: user.email, dreams});
    });
  }catch(err){
    return res.redirect('/login');
  }
});

app.delete('/dream/delete/:id', async (req, res) => {
  try {
    const user = await auth.jwt.verify(req);
    const dreamId = parseInt(req.params.id);

    db.run(
      `DELETE FROM dreams WHERE id = ? AND author = ?`,
      [dreamId, user.email],
      function (err) {
        if (err) return res.json({ success: false, message: err.message });
        if (this.changes === 0)
          return res.json({ success: false, message: "Dream not found or unauthorized" });

        return res.json({ success: true });
      }
    );
  } catch (err) {
    return res.json({ success: false, message: err.message });
  }
});

app.put('/dream/edit/:id', (req, res) => {
  const dreamId = req.params.id;
  const { dream } = req.body;

  db.run(`UPDATE dreams SET dream = ? WHERE id = ?`, [dream, dreamId], (err) => {
    if (err) return res.json({ success: false });
    res.json({ success: true });
  });
});

app.get('/notifications', async (req, res) => {
  try {
    const user = await auth.jwt.verify(req);

    db.all(
      `SELECT * FROM notifications WHERE user_email = ? ORDER BY created_at DESC`,
      [user.email],
      (err, notifications) => {
        if (err) return res.status(500).json({ success: false, message: err.message });

        db.get(
          `SELECT COUNT(*) AS count FROM notifications WHERE user_email = ? AND is_read = 0`,
          [user.email],
          (err2, result) => {
            if (err2) return res.status(500).json({ success: false, message: err2.message });

            const unreadCount = result.count || 0;
            res.render('notifications', { notifications, unreadCount });
          }
        );
      }
    );
  } catch (err) {
    console.error(err);
    res.redirect('/login');
  }
});

app.post('/notifications/read/:id', async (req, res) => {
  try {
    const user = await auth.jwt.verify(req);
    const notifId = parseInt(req.params.id);

    db.run(
      `UPDATE notifications SET is_read = 1 WHERE id = ? AND user_email = ?`,
      [notifId, user.email],
      function (err) {
        if (err)
          return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true });
      }
    );
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete('/notifications/clear', async (req, res) => {
  try {
    const user = await auth.jwt.verify(req);
    db.run(
      `DELETE FROM notifications WHERE user_email = ?`,
      [user.email],
      function (err) {
        if (err)
          return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true });
      }
    );
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/profile', async (req, res) => {
  try {
    const user = await auth.jwt.verify(req);
    res.render('profile', { user });
  } catch (err) {
    return res.redirect('/login');
  }
});

app.put('/profile/update', async (req, res) => {
  try {
    const user = await auth.jwt.verify(req);
    const { username, password } = req.body;

    if (!username && !password)
      return res.json({ success: false, message: "Nothing to update" });

    const updates = [];
    const params = [];

    if (username) {
      updates.push("username = ?");
      params.push(username);
    }
    if (password) {
      const hashed = await bcrypt.hash(password, 10);
      updates.push("password = ?");
      params.push(hashed);
    }

    params.push(user.email);

    db.run(
      `UPDATE users SET ${updates.join(", ")} WHERE email = ?`,
      params,
      (err) => {
        if (err) return res.json({ success: false, message: err.message });
        res.json({ success: true, message: "✅ Profile updated successfully!" });
      }
    );
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});



// app.listen(3000, ()=>{ console.log('Server is running...')});
server.listen(3000, () => console.log("🚀 Server on 3000"));