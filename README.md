# Passport-wechat-auth

[Passport](http://passportjs.org/) strategies for authenticating with [wechat]
using OAuth 1.0a and OAuth 2.0.

This module lets you authenticate using wechat in your Node.js applications.
By plugging into Passport, wechat authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-wechat-auth

## Usage of OAuth 2.0

#### Configure Strategy

The wechat OAuth 2.0 authentication strategy authenticates users using a wechat
account and OAuth 2.0 tokens.  The strategy requires a `verify` callback, which
accepts these credentials and calls `done` providing a user, as well as
`options` specifying a app ID, app secret, and callback URL.

    passport.use(new GoogleStrategy({
        appId: WECHAT_APP_ID,
        appSecret: WECHAT_APP_SECRET,
        callbackURL: "http://127.0.0.1:3000/auth/wechat/callback"
      },
      function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({ openid: profile.openid }, function (err, user) {
          return done(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'wechat'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/wechat',
      passport.authenticate('wechat'));

    app.get('/auth/wechat/callback', 
      passport.authenticate('wechat', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });
