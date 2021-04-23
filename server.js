'use strict';
const express = require('express');
const bodyParser = require('body-parser');
const passport = require('passport');
const xssec = require('@sap/xssec');
const JWTStrategy = require('@sap/xssec').JWTStrategy;
const xsenv = require('@sap/xsenv');

function log(logTxt) {
  console.log(logTxt);
}

function logJWT(req) {
  var jwt = req.header('authorization');
  if (!jwt) {
    log('No JWT in Request - Call performed directly to App');
    return;
  }
  jwt = jwt.substring('Bearer '.length);
  log('JWT is: ' + jwt);
  xssec.createSecurityContext(
    jwt,
    xsenv.getServices({ uaa: 'nodeauth-uaa' }).uaa,
    function (error, securityContext) {
      if (error) {
        log('Security Context creation failed');
        return;
      }
      log('Security Context created successfully');
      var userInfo = {
        logonName: securityContext.getLogonName(),
        giveName: securityContext.getGivenName(),
        familyName: securityContext.getFamilyName(),
        email: securityContext.getEmail(),
      };
      log('User Info retrieved successfully ' + JSON.stringify(userInfo));
    }
  );

  if (req.user) {
    var myUser = JSON.stringify(req.user);
    var myUserAuth = JSON.stringify(req.authInfo);
    log(
      '2nd. XsSec API - user: ' + myUser + ' Security Context: ' + myUserAuth
    );
  }
  // see it using: cf logs appname --recent
}

const app = express();
app.use(bodyParser.json());
app.use((req, res, next) => {
  next();
});

passport.use(new JWTStrategy(xsenv.getServices({ uaa: { tag: 'xsuaa' } }).uaa));
app.use(passport.initialize());
app.use(passport.authenticate('JWT', { session: false }));

app.get('/', function (req, res) {
//  logJWT(req);
  res.status(200).json({
    msg: 'Hello world!',
  });
});

app.get('/test', function (req, res) {
  res.status(200).json({
    msg: 'Hello test!',
  });
});

app.get('/flp', function (req, res) {
  res.status(200).json({
    icon: 'sap-icon://product',
    info: '',
    infoState: '',
    number: 700,
    numberDigits: 1,
    numberFactor: 'M',
    numberState: 'Postiive',
    numberUnit: 'CAD',
    stateArrow: '',
    subtitle: 'CFLP sub',
    targetParams: '',
    title: 'CFLP title',
  });
});

app.get('/protected', function (req, res) {
  logJWT(req);
  if (!req.authInfo.checkLocalScope('Update')) {
    log('Missing the expected scope');
    res.status(403).end('Forbidden Blabla');
    return;
  }
  res.status(200).json({
    msg: 'Authorized',
  });
});

const PORT = process.env.PORT || 8088;

var server = app.listen(PORT, function () {
  const host = server.address().address;
  const port = server.address().port;

  log('Example app listening at http://' + host + ':' + port);
});
