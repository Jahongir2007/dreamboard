const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./dreamboard.db", (err) => {
  if (err) console.error("❌ DB connection failed:", err);
  else console.log("✅ Connected to SQLite database.");
});

db.all(`SELECT * FROM dreams`, (err, dreams)=>{
    if(err) console.log(err);
    console.log(dreams);
});