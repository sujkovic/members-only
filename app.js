const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
require("dotenv").config();
const bcrypt = require("bcryptjs");
const { body, check, validationResult } = require("express-validator");

mongoose.connect(process.env.mongodb_url, {
  useUnifiedTopology: true,
  useNewUrlParser: true,
});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    firstname: { type: String, required: true },
    lastname: { type: String, required: true },
    isMember: { type: Boolean },
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

const Message = mongoose.model(
  "Message",
  new Schema({
    user: { type: String, required: true },
    date: { type: String, required: true },
    text: { type: String, required: true },
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));

//      Passport

passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err, user) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      bcrypt.compare(password, user.password, (err2, res) => {
        if (res) {
          return done(null, user); //  gucci
        } else {
          return done(null, false, { message: "Incorect password" });
        }
      });
    });
  })
);

//  cookies
passport.serializeUser(function (user, done) {
  done(null, user.id);
});
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

//  keep global var of user
app.use(function (req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res, next) => {
  Message.find()
    .sort([["date", "descending"]])
    .exec(function (err, msgs) {
      if (err) {
        return next(err);
      }
      res.render("index", {
        user: req.user,
        messages: msgs,
      });
    });
});
app.get("/sign-up", (req, res) => res.render("sign-up"));
app.post("/sign-up", [
  body("firstname", "First name required").trim().isLength({ min: 1 }),
  body("lastname", "Last name required").trim().isLength({ min: 1 }),
  body("username", "Username required").trim().isLength({ min: 1 }),
  body("password", "Password must be at least 8 characters").isLength({
    min: 8,
  }),
  check("confirmpassword", "Passwords must match")
    .exists()
    .custom((value, { req }) => value === req.body.password),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log(errors.array());
      res.render("sign-up", { user: req.body, errors: errors.array() });
      return;
    }
    const user = new User({
      firstname: req.body.firstname,
      lastname: req.body.lastname,
      isMember: false,
      username: req.body.username,
      password: req.body.password,
    });
    bcrypt.hash(user.password, 10, (err, hashedPassword) => {
      user.password = hashedPassword;
      user.save((err) => {
        if (err) {
          return next(err);
        }
        res.redirect("/");
      });
    });
  },
]);

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

app.get("/member-sign-up", (req, res) => res.render("member-sign-up"));
app.post("/member-sign-up", (req, res, next) => {
  if (req.body.code === process.env.secret_code) {
    /*
    const tempuser = new User({
      firstname: req.user.firstname,
      lastname: req.user.lastname,
      username: req.user.username,
      password: req.user.password,
      isMember: true,
    });
    */
    const tempuser = req.user;
    tempuser.isMember = true;
    User.findByIdAndUpdate(req.user.id, tempuser, {}, (err, theuser) => {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
  } else {
    res.render("member-sign-up", { failure: true });
  }
});

app.get("/create-message", (req, res) => {
  res.render("create-message");
});
app.post("/create-message", (req, res, next) => {
  let curDate = new Date();
  curDate =
    curDate.getMonth() + "/" + curDate.getDate() + "/" + curDate.getFullYear();
  const message = new Message({
    text: req.body.text,
    date: curDate,
    user: req.user.username,
  });
  message.save((err) => {
    if (err) {
      next(err);
    }
    res.redirect("/");
  });
});

app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.listen(3000, () => console.log("app listening on port 3000!"));
