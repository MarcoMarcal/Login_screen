const express = require('express')
const app = express()
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const bcrypt = require('bcrypt')
const multer = require('multer')
const fs = require('fs')
var crypto = require('crypto');

LocalStrategy = require('passport-local').Strategy;

passport.serializeUser(function (user, done) {
  done(null, user._id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new LocalStrategy(
  function (username, password, done) {
    User.findOne({
      email: username
    }, (err, user) => {
      if (err) return done(err)
      if (!user) return done(null, false, { message: 'User not found!' });
      bcrypt.compare(password, user.password, function(err, res) {
        if (err) return done(err)
        if (res) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password!' });
        }
      })
    })
  }
));

function loggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    next()
  } else {
    req.flash('error', 'Faça seu login');
    res.redirect('/login')
  }
}

var MongoDBStore = require('connect-mongodb-session')(session);

const mongoString = "mongodb+srv://gabrielprr:3SVHy4GRR4aK9t@ubuntuservernas.gtmk9.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"

var store = new MongoDBStore({
  uri: mongoString,
  collection: 'users'
});

/* ************ */
app.use(express.static(__dirname + '/public'));
app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session({
  secret: 'This is a secret - Make sure to change!',
  cookie: {
    maxAge: 1000 * 60 * 60 // 1000ms, 60seconds, 60hour
  },
  store: store,
  resave: true,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

const mongoose = require('mongoose');
mongoose.connect(mongoString, { useNewUrlParser: true, useUnifiedTopology: true }).catch(err => console.log(err.reason));
mongoose.connection.on('error', console.error.bind(console, 'connection error:'));
mongoose.connection.once('open', function() {
  // we're connected on mongoose!
  console.log('connected on mongoose');
});


const Schema = mongoose.Schema;

const userSchema = new Schema({
  email: String,
  password: String,
  iduser: String
});

const User = mongoose.model('users', userSchema);

app.post('/register', async (req, res, next) => {
  const user = await User.findOne({
    email: req.body.email
  })

  if (user) {
    req.flash('error', 'Sorry, that name is taken. Maybe you need to <a href="/login">login</a>?');
    res.redirect('/register');
  } else if (req.body.email == "" || req.body.password == "") {
    req.flash('error', 'Please fill out all the fields.');
    res.redirect('/register');
  } else {
    bcrypt.genSalt(10, function (err, salt) {
      if (err) return next(err);
      bcrypt.hash(req.body.password, salt, function (err, hash) {
        if (err) return next(err);
        var sha256 = crypto.createHash('sha256').update(req.body.email).digest('hex');
        const folder = "uploads/" + sha256;
        fs.mkdirSync(folder)
        new User({
          email: req.body.email,
          password: hash,
          encodesha256: sha256
        }).save()
        req.flash('info', 'Account made, please log in...');
        res.redirect('/login');
      });
    });
  }
});

app.post('/login', passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login', failureFlash: true }))


app.get('/login', (req, res) => {
  res.render('login.ejs')
})

app.get('/register', (req, res) => {
  res.render('register.ejs')
})

app.get('/logout', (req, res) => {
  req.logOut()
  res.redirect('/login')
})

const path = require('path')

app.get('/', loggedIn, async (req, res, next) => {
  var sha256 = crypto.createHash('sha256').update(req.user.email).digest('hex');
  console.log("User: "+ req.user.email+ " Id: "+sha256)
  const fullPath = 'uploads/'+sha256;
  
  let files = fs.readdirSync(fullPath);

  console.log(files);

  res.render('index.ejs', {
    email: req.user.email,
    files: files
  })
  next()
})




app.post('/upload', loggedIn, function(req, res, next){
  console.log(`User: ${req.user.email} starting uploading files...`)//uploading Start
  var sha256 = crypto.createHash('sha256').update(req.user.email).digest('hex');
  var storage = multer.diskStorage({
        destination: function (req, file, cb) {
          cb(null, ('uploads/' +sha256) )
        },
        filename: function (req, file, cb) {
          cb(null, Date.now() + '-' + file.originalname)
        }
      })

  //var upload = multer({ dest: ('hidden/images/slip/' + req.body.classId) }).single('file')
  var upload = multer({ storage:storage }).array("file", 10)
  upload(req,res,function(err) {
      if(err) {
          return handleError(err, res);
      }
      console.log(`User: ${req.user.email} Complete upload files`)//uploading Start
      res.json({"status":"completed"});
  });
})

const port = '3000';
console.log(`listening on http://192.168.15.145:${port}`)
app.listen(process.env.PORT || 3000, process.env.IP || '0.0.0.0');