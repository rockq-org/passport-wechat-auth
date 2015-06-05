/**
 * Module dependencies.
 */
var util = require('util'),
    querystring = require('querystring'),
    OAuth2Strategy = require('passport-utils').OAuth2Strategy,
    InternalOAuthError = require('passport-utils').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Google authentication strategy authenticates requests by delegating to
 * Google using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Google application's client id
 *   - `clientSecret`  your Google application's client secret
 *   - `callbackURL`   URL to which Google will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new GoogleStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/google/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  this._authorizeUrl = options.authorizationURL || 'https://open.weixin.qq.com/connect/oauth2/authorize';
  this._accessTokenUrl = options.tokenURL || 'https://api.weixin.qq.com/sns/oauth2/access_token';
  
  OAuth2Strategy.call(this, options, verify);
  this.name = 'wechat';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


Strategy.prototype.checkOAuthParams = function(options){
    if (!options.appId) throw new Error('WechatStrategy requires a appId option');
    else this._appId = options.appId;
    if (!options.appSecret) throw new Error('WechatStrategy requires a appSecret option');
    else this._appSecret = options.appSecret;
};

/**
 * Retrieve user profile from Google.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `google`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, accessTokenResult, done) {
    var that = this;
    var profileURL = 'https://api.weixin.qq.com/sns/userinfo';
    if(accessTokenResult.scope == 'snsapi_base'){
        //TODO it's not working yet , the access token is not this one.
        profileURL = 'https://api.weixin.qq.com/cgi-bin/user/info';
    }
    var params = {
        openid:accessTokenResult.openid,
        lang:'zh_CN'
    }
    params[this._accessTokenName] = accessToken;
    this._request('GET', profileURL, null, params, function (err, body, res){
        if(err){
            return done(new InternalOAuthError('failed to fetch user profile', err));
        }
        try{
            var json = JSON.parse(body);
            var profile = { provider: that.name };
            profile.id = json.openid;
            profile.displayName = json.nickname;
            profile.username = json.nickname;
            profile.email = json.email;

            profile._raw = body;
            profile._json = json;

            done(null, profile);
        }catch(e) {
            done(e);
        }
    });
};

/**
 * rewrite OAuth2Strategy getOAuthAccessToken method to fit wechat.
 * @params {Object} request params.
 */
Strategy.prototype.getOAuthAccessToken = function(params, callback){
    //send request
    this._request("GET", this._getAccessTokenUrl(), null, params, function(error, data, response) {
        if( error )  callback(error);
        else {
            var results;
            try {
                // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
                // responses should be in JSON
                results= JSON.parse( data );
            }
            catch(e) {
                // .... However both Facebook + Github currently use rev05 of the spec
                // and neither seem to specify a content-type correctly in their response headers :(
                // clients of these services will suffer a *minor* performance cost of the exception
                // being thrown
                results= querystring.parse( data );
            }
            var access_token= results["access_token"];
            var refresh_token= results["refresh_token"];
            delete results["refresh_token"];
            callback(null, access_token, refresh_token, results); // callback results =-=
        }
    });
};

/**
 * Return extra Google-specific parameters to be included in the authorization
 * request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
    var params = {};
    params['appid'] = this._appId;
    params['redirect_uri'] = options.callbackURL;
    params['response_type'] = 'code';
    var scope = options.scope || this._scope;
    if (scope) {
        if (Array.isArray(scope)){
            scope = scope.join(this._scopeSeparator);
        }
        params.scope = scope;
    }
    if (options.state){
        params.state = options.state;
    }
    return params;
};

Strategy.prototype.accessTokenParams = function(code,options){
    var params = {};
    params['appid'] = this._appId;
    params['secret'] = this._appSecret;
    params['code']= code;
    params['grant_type'] = options.grantType || 'authorization_code';
    return params;
};

Strategy.prototype.getAuthorizeUrl = function(params){
    return this._baseSite + this._authorizeUrl + "?" + querystring.stringify(params) + '#wechat_redirect';
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
