import express from 'express';
import mongoose from 'mongoose';
import dotenv from "dotenv";
import cors from 'cors';
import session from 'express-session';
import passport from 'passport';
import User from './User';
import { IMongoDBUser } from './types';
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github').Strategy;

dotenv.config();

const app = express();

//connexion mongoDB
mongoose.connect(`${process.env.START_MONGODB}${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}${process.env.END_MONGODB}`, {

}, () => {
    console.log("Connexion à mongoDB réussie !")
});

//middleware
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(
    session({
        secret: "secretcode",
        resave: true,
        saveUninitialized: true
    })
);
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user: IMongoDBUser, done: any) => {
    return done(null, user._id) //pas d'erreur, on renvoie user. On "serialize" id only = safe practice
})

passport.deserializeUser((id: string, done: any) => {
    User.findById(id, (err: Error, doc: IMongoDBUser) => {
        return done(null, doc)
    })

})

//strategies
passport.use(new GoogleStrategy({
    clientID: `${process.env.GOOGLE_CLIENT_ID}`,
    clientSecret: `${process.env.GOOGLE_CLIENT_SECRET}`,
    callbackURL: "/auth/google/callback"
},
    function (_: any, __: any, profile: any, cb: any) {
        //Successful authentication, new User into DB
        //console.log(profile)
        User.findOne({ googleId: profile.id }, async (err: Error, doc: IMongoDBUser) => {
            if (err) {
                return cb(err, null) //si erreur, on la reçoit. null = pas de nouveau user
            }
            if (!doc) {
                //si no user (doc = ce qu'on recoit de mongoDB) => creation de l'user
                const newUser = new User({
                    googleId: profile.id,
                    username: profile.name.givenName
                });
                await newUser.save(); //on attend qu'il soit créé pour continuer
                cb(null, newUser.googleId); // si doc n'existe pas, callback(pas d'erreur, nouveau profil).on stock id only
            }
            cb(null, doc) //si doc existe, on l'utilise
        })
    }
));

passport.use(new GitHubStrategy({
    clientID: `${process.env.GITHUB_CLIENT_ID}`,
    clientSecret: `${process.env.GITHUB_CLIENT_SECRET}`,
    callbackURL: "/auth/github/callback"
},
    function (_: any, __: any, profile: any, cb: any) {
        User.findOne({ githubId: profile.id }, async (err: Error, doc: IMongoDBUser) => {
            if (err) {
                return cb(err, null)
            }
            if (!doc) {
                const newUser = new User({
                    githubId: profile.id,
                    username: profile.username
                });
                await newUser.save();
                cb(null, newUser.githubId);
            }
            cb(null, doc);
        })
    }
));


app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('http://localhost:3000');
    });

app.get('/auth/github',
    passport.authenticate('github', { scope: ['profile'] }));

app.get('/auth/github/callback',
    passport.authenticate('github', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('http://localhost:3000');
    });


//routes
app.get('/', (req, res) => {
    res.send('Hello World');
});

app.get('/getuser', (req, res) => {
    res.send(req.user);
})

app.get('/auth/logout', (req, res) => {
    req.logout();
    res.send('done');
});

app.listen(process.env.PORT || 4000, () => {
    console.log("Server started");
});