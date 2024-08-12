import express from "express";
import bcrypt from "bcrypt";
import pg from "pg";
import env from "dotenv";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";

const app = express();
const PORT = process.env.PORT || 3000;
const minLength = 8, maxLength = 20; // of username and password
const saltRounds = 10;

env.config();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(express.urlencoded({ extended: true }));

// Database configuration
const db = new pg.Client({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});

db.connect();

app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secret.ejs");
  } else {
    res.render("login.ejs");
  }
});

app.get("/create", (req, res) => {
  if (!req.isAuthenticated())
    res.render("create.ejs");
  else
    res.redirect("/secret");
});

app.post("/create", async (req, res) => {
  const username = req.body.username, password = req.body.password;

  const isUsernameValidObj = validate(username, "username", minLength, maxLength, false);
  if (isUsernameValidObj.isValid === false) {
    res.render("create.ejs", { message: isUsernameValidObj.msg });
    return;
  }


  const isPasswordValidObj = validate(password, "password", minLength, maxLength, true);
  if (isPasswordValidObj.isValid === false) {
    res.render("create.ejs", { message: isPasswordValidObj.msg });
    return;
  }

  try {
    const isExistingUsername = await db.query("SELECT * FROM users WHERE username=$1", [username]);
    if (isExistingUsername.rowCount === 0) {
      const hash = await bcrypt.hash(password, saltRounds);
      const currentDate = new Date();
      const dateOfJoining = `${currentDate.getFullYear()}-${(currentDate.getMonth() + 1).toString().padStart(2, '0')}-${(currentDate.getDate()).toString().padStart(2, '0')}`;

      const returning = await db.query("INSERT INTO users(username, password, date_of_joining) values ($1, $2, $3) RETURNING *", [username, hash, dateOfJoining]);
      const user = returning.rows[0];
      req.login(user, (err) => {
        if (err) {
          console.log("Account is created but error while logging in : " + err.stack);
          res.redirect("/login");
        } else {
          res.redirect("/secret");
        }
      })
    } else {
      res.render("create.ejs", { message: "Username already taken!" });
    }
  } catch (err) {
    console.log(err);
    res.render("create.ejs", { message: "Some error occurred ! please try again !" });
  }
});

app.get("/login", (req, res) => {
  console.log(req.session);

  if (req.session.messages) {
    const message = req.session.messages[0];
    req.session.messages = [];
    res.render("login.ejs", { message: message })
  }
  else
    res.render("login.ejs");
})

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secret",
  failureRedirect: "/login",
  failureMessage: true
}));

app.post("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) return next(err);
    res.redirect("/");
  })
})

app.get("/secret", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secret.ejs");
  } else {
    res.redirect("/");
  }
})

function validate(text, textName, minLength, maxLength, isAPassword) {
  let result = { isValid: true, msg: "Valid" };

  if (text.length === 0) {
    result['isValid'] = false;
    result['msg'] = `${textName} is blank!`;
  }
  else if (text.length < minLength || text.length > maxLength) {
    result['isValid'] = false;
    result['msg'] = `${textName} length must be in the range of [${minLength} - ${maxLength}] !`;
  }
  else if (!isAPassword) {
    // Otherwise it's a username, which can start with _ or A-Z or a-z and can contain digits, and cannot contain a space
    result['isValid'] = /^[_a-zA-Z][\w]*$/.test(text);
    if (result['isValid'] === false) {
      result['msg'] = `${textName} must not contain spaces and must start with _ or A-Z or a-z and can contain digits 0-9 after that.`
    }
  }

  return result;
}

passport.use(new Strategy(async function verify(username, password, cb) {
  const isUsernameValidObj = validate(username, "username", minLength, maxLength, false);
  if (isUsernameValidObj.isValid === false) {
    return cb(null, false, { message: isUsernameValidObj.msg });
  }

  const isPasswordValidObj = validate(password, "password", minLength, maxLength, true);
  if (isPasswordValidObj.isValid === false)
    return cb(null, false, { message: isPasswordValidObj.msg });

  try {
    const doesUserExist = await db.query("SELECT * FROM users WHERE username=$1", [username]);

    if (doesUserExist.rowCount === 1) {
      const storedPassword = doesUserExist.rows[0].password;
      const isPasswordTrue = await bcrypt.compare(password, storedPassword);
      const user = doesUserExist.rows[0];
      if (isPasswordTrue) {
        return cb(null, user, { message: "Successfully logged in !" });
      } else {
        return cb(null, false, { message: "Wrong username or password !" });
      }
    } else {
      return cb(null, false, { message: "Wrong username !" });
    }
  } catch (err) {
    return cb(null, false, { message: err.stack });
  }

}));

passport.serializeUser((user, cb) => cb(null, user.user_id));

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT username, user_id FROM users WHERE user_id=$1", [id]);
    if (result.rowCount === 1)
      return cb(null, result.rows[0]);
    else
      return cb("User not found in the db");
  } catch (err) {
    console.log("Error during deserializing the user : " + err.stack);
    return cb(err.stack);
  }
})


app.listen(PORT, () => {
  console.log(`Server is up and running on http://localhost:${PORT}`);
});