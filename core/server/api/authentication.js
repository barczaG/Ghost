var _                = require('lodash'),
    dataProvider     = require('../models'),
    settings         = require('./settings'),
    mail             = require('./mail'),
    globalUtils      = require('../utils'),
    utils            = require('./utils'),
    Promise          = require('bluebird'),
    errors           = require('../errors'),
    config           = require('../config'),
    co               = require('co'),
    authentication;

var setupTasks = co.wrap(function * (object) {
    var setupUser,
        internal = {context: {internal: true}};

    var checkedSetupData = yield utils.checkObject(object, 'setup');
    setupUser = {
        name: checkedSetupData.setup[0].name,
        email: checkedSetupData.setup[0].email,
        password: checkedSetupData.setup[0].password,
        blogTitle: checkedSetupData.setup[0].blogTitle,
        status: 'active'
    };
    var ownerUser = yield dataProvider.User.findOne({role: 'Owner', status: 'all'});
    var user;
    if (ownerUser) {
        user = yield dataProvider.User.setup(setupUser, _.extend({id: ownerUser.id}, internal));
    } else {
        var ownerRole = yield dataProvider.Role.findOne({name: 'Owner'});
        setupUser.roles = [ownerRole.id];
        user = yield dataProvider.User.add(setupUser, internal);
    }
    
    var userSettings = [];

    // Handles the additional values set by the setup screen.
    if (!_.isEmpty(setupUser.blogTitle)) {
        userSettings.push({key: 'title', value: setupUser.blogTitle});
        userSettings.push({key: 'description', value: 'Thoughts, stories and ideas.'});
    }

    setupUser = user.toJSON(internal);
    yield settings.edit({settings: userSettings}, {context: {user: setupUser.id}});

    return setupUser;
});

/**
 * ## Authentication API Methods
 *
 * **See:** [API Methods](index.js.html#api%20methods)
 */
authentication = {

    /**
     * ## Generate Reset Token
     * generate a reset token for a given email address
     * @param {Object} object
     * @returns {Promise(passwordreset)} message
     */
    generateResetToken: co.wrap(function * generateResetToken(object) {
        var expires = Date.now() + globalUtils.ONE_DAY_MS;

        yield authentication.isSetupCompleted();

        var checkedPasswordReset = yield utils.checkObject(object, 'passwordreset');
        var email;
        if (checkedPasswordReset.passwordreset[0].email) {
            email = checkedPasswordReset.passwordreset[0].email;
        } else {
            throw new errors.BadRequestError('No email provided.');
        }

        var response = yield settings.read({context: {internal: true}, key: 'dbHash'});
        var dbHash = response.settings[0].value;
        var resetToken = yield dataProvider.User.generateResetToken(email, expires, dbHash);
        var baseUrl = config.forceAdminSSL ? (config.urlSSL || config.url) : config.url,
            resetUrl = baseUrl.replace(/\/$/, '') + '/ghost/reset/' + globalUtils.encodeBase64URLsafe(resetToken) + '/';

        var emailContent = yield mail.generateContent({data: {resetUrl: resetUrl}, template: 'reset-password'});
        var payload = {
            mail: [{
                message: {
                    to: email,
                    subject: 'Reset Password',
                    html: emailContent.html,
                    text: emailContent.text
                },
                options: {}
            }]
        };
        yield mail.send(payload, {context: {internal: true}});

        return {passwordreset: [{message: 'Check your email for further instructions.'}]};
    }),

    /**
     * ## Reset Password
     * reset password if a valid token and password (2x) is passed
     * @param {Object} object
     * @returns {Promise(passwordreset)} message
     */
    resetPassword: co.wrap(function * resetPassword(object) {
        yield authentication.isSetupCompleted();

        var checkedPasswordReset = yield utils.checkObject(object, 'passwordreset');
        var resetToken = checkedPasswordReset.passwordreset[0].token;
        var newPassword = checkedPasswordReset.passwordreset[0].newPassword;
        var ne2Password = checkedPasswordReset.passwordreset[0].ne2Password;

        var response = yield settings.read({context: {internal: true}, key: 'dbHash'});
        var dbHash = response.settings[0].value;
        try {
            yield dataProvider.User.resetPassword({
                token: resetToken,
                newPassword: newPassword,
                ne2Password: ne2Password,
                dbHash: dbHash
            });
        } catch (error) {
            throw new errors.UnauthorizedError(error.message);
        }
        return {passwordreset: [{message: 'Password changed successfully.'}]};
    }),

    /**
     * ### Accept Invitation
     * @param {User} object the user to create
     * @returns {Promise(User}} Newly created user
     */
    acceptInvitation: co.wrap(function * acceptInvitation(object) {
        yield authentication.isSetupCompleted();

        var checkedInvitation = yield utils.checkObject(object, 'invitation');
        var resetToken = checkedInvitation.invitation[0].token;
        var newPassword = checkedInvitation.invitation[0].password;
        var ne2Password = checkedInvitation.invitation[0].password;
        var email = checkedInvitation.invitation[0].email;
        var name = checkedInvitation.invitation[0].name;

        var response = yield settings.read({context: {internal: true}, key: 'dbHash'});
        var dbHash = response.settings[0].value;
        var user;
        try {
            user = yield dataProvider.User.resetPassword({
                token: resetToken,
                newPassword: newPassword,
                ne2Password: ne2Password,
                dbHash: dbHash
            });
        } catch (error) {
            throw new errors.UnauthorizedError(error.message);
        }

        yield dataProvider.User.edit({name: name, email: email, slug: ''}, {id: user.id});

        return {invitation: [{message: 'Invitation accepted.'}]};
    }),

    /**
     * ### Check for invitation
     * @param {Object} options
     * @param {string} options.email The email to check for an invitation on
     * @returns {Promise(Invitation}} An invitation status
     */
    isInvitation: co.wrap(function * isInvitation(options) {
        yield authentication.isSetupCompleted();

        if (options.email) {
            var response = dataProvider.User.findOne({email: options.email, status: 'invited'});
            if (response) {
                return {invitation: [{valid: true}]};
            } else {
                return {invitation: [{valid: false}]};
            }
        } else {
            throw new errors.BadRequestError('The server did not receive a valid email');
        }
    }),

    isSetupCompleted: co.wrap(function * () {
        var result = yield authentication.isSetup();
        var setup = result.setup[0].status;

        if (!setup) {
            throw new errors.NoPermissionError('Setup must be completed before making this request.');
        }
    }),

    isSetup: co.wrap(function * isSetup() {
        var users =  yield dataProvider.User.query(function (qb) {
            qb.whereIn('status', ['active', 'warn-1', 'warn-2', 'warn-3', 'warn-4', 'locked']);
        }).fetch();
        if (users) {
            return {setup: [{status: true}]};
        } else {
            return {setup: [{status: false}]};
        }
    }),

    setup: co.wrap(function * setup(object) {
        var result = yield authentication.isSetup();
        var _setup = result.setup[0].status;

        if (_setup) {
            throw new errors.NoPermissionError('Setup has already been completed.');
        }

        var setupUser = yield setupTasks(object);

        var data = {
            ownerEmail: setupUser.email
        };
        var emailContent = yield mail.generateContent({data: data, template: 'welcome'});
        var message = {
            to: setupUser.email,
            subject: 'Your New Ghost Blog',
            html: emailContent.html,
            text: emailContent.text
        };
        var payload = {
            mail: [{
                message: message,
                options: {}
            }]
        };
        
        try {
            yield mail.send(payload, {context: {internal: true}});
        } catch (error) {
            errors.logError(
                error.message,
                'Unable to send welcome email, your blog will continue to function.',
                'Please see http://support.ghost.org/mail/ for instructions on configuring email.'
            );
        }

        return {users: [setupUser]};
    }),

    updateSetup: co.wrap(function * updateSetup(object, options) {
        if (!options.context || !options.context.user) {
            throw new errors.NoPermissionError('You are not logged in.');
        }

        var result = yield dataProvider.User.findOne({role: 'Owner', status: 'all'});
        var user = result.toJSON();

        if (user.id !== options.context.user) {
            throw new errors.NoPermissionError('You are not the blog owner.');
        }

        var result2 = yield setupTasks(object);
        return {users: [result2]};
    }),

    revoke: co.wrap(function * (object) {
        var token;

        if (object.token_type_hint && object.token_type_hint === 'access_token') {
            token = dataProvider.Accesstoken;
        } else if (object.token_type_hint && object.token_type_hint === 'refresh_token') {
            token = dataProvider.Refreshtoken;
        } else {
            return errors.BadRequestError('Invalid token_type_hint given.');
        }

        try {
            yield token.destroyByToken({token: object.token});
        } catch (error) {
            return {token: object.token, error: 'Invalid token provided'};
        }
        return {token: object.token};
    })
};

module.exports = authentication;
