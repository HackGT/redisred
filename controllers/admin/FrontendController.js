var request = require('request');
var redirectModel = require('../../models/Redirect');

module.exports = function(redis, passport, authService) {
  var Redirect = redirectModel(redis);
  var FrontendController = {};

  if (authService && authService.url && authService.cookie) {
    console.log("Using central auth service", authService.url);

    FrontendController.authenticate = function(req, res, next) {
      var token = req.cookies[authService.cookie];
      var proto = req.secure ? "https://" : "http://";
      var callback = proto + req.headers.host + req.originalUrl; // TODO: validate url
      request({
        method: 'POST',
        url: authService.url + "/graphql",
        json: true,
        body: {
          query: "{" + ([
            "user(token:\"" + token + "\"){admin}",
            "authenticate(callback:\"" + callback + "\")"
          ].join("\n")) + "}"
        }
      }, function(err, response, body) {
        if (body && body.data && body.data.user) {
          if (body.data.user.admin) {
            next();
          } else {
            res.status(401).send('You do not have permission to access this path');
          }
        } else if (body && body.data && body.data.authenticate) {
          res.redirect(body.data.authenticate);
        } else {
          console.error("Failed to connect to auth service:", authService.url);
          console.error(response, body);
          res.status(500).send('Could not connect to central auth.');
        }
      });
    };

    FrontendController.showLogin = function(req, res) {
      res.redirect('/admin/redirects');
    };

    FrontendController.logout = function(req, res) {
      request({
        method: 'POST',
        url: authService.url + "/graphql",
        json: true,
        body: {
          query: "{logout}"
        }
      }, function(err, response, body) {
        if (!body || !body.data || !body.data.logout) {
          console.error("Failed to connect to auth service:", authService.url);
          console.error(response, body);
          res.status(500).send('Could not connect to central auth.');
        } else {
          res.redirect(body.data.logout);
        }
      });
    };

    FrontendController.login = function(req, res) {
      FrontendController.showLogin(req, res);
    };
  } else {
    //Authentication stuff...
    FrontendController.authenticate = function(req, res, next) {
      if (req.isAuthenticated()) next();
      else res.redirect('/admin');
    };

    FrontendController.showLogin = function(req, res) {
      if (req.isAuthenticated()) res.redirect('/admin/redirects');
      else res.render('admin/root');
    };

    FrontendController.login = passport.authenticate('local', {
      successRedirect: '/admin/redirects',
      failureRedirect: '/admin#incorrect'
    });

    FrontendController.logout = function(req, res) {
      req.session.destroy(function () {
        res.redirect('/admin');
      });
    };
  }


  //Actual display logic
  FrontendController.getAllRedirects = function(req, res) {
    Redirect.getAll(function(err, redirects) {
      if (err)
        res.status(500).send(err);
      else {
        res.status(200).render('admin/redirects', { redirects: redirects, token: req.csrfToken() });
      }
    });
  };

  FrontendController.createRedirect = function(req, res) {
    var key = req.body.key;
    var url = req.body.url;
    if (!key || !url) {
      res.status(400).send("You failed to supply all of the parameters.");
      return;
    }
    Redirect.create(key, url, function(err, redirect) {
      if (err)
        res.status(500).send(err);
      else
        res.redirect('/admin/redirects');
    });
  };

  FrontendController.deleteRedirect = function(req, res) {
    var key = req.body.key;
    if (!key) {
      res.status(400).send("You failed to supply all of the parameters.");
      return;
    }
    Redirect.delete(key, function(err) {
      if (err)
        res.status(500).send(err);
      else
        res.redirect('/admin/redirects');
    });
  };

  return FrontendController;
};
