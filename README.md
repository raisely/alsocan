AlsoCan is an authorization library. It's a replacement for CanCan with additonal features:

Features: 
* Export all permissions of a given user to load them up on the front end
* Support for explicity deny
* Rich debugging output to show exactly why an action was allowed or denied
* Wildcard actions
* Zero dependencies

Usage

```
npm install alsocan
```

```
const AlsoCan = require('./alsoCan');

const alsoCan = new AlsoCan({
	targetCompare: (instance, model) => instance instanceof model,
	userCompare: (user, role) => user.role === role,
    // Will print debug info to the console if truthy
	debug: process.env.DEBUG_AUTHORIZATION,
	defaultUser: user => user || { name: 'general public', permission: 'public' }
});

class Posts {};
const isSameOrg = (user, target, ctx, action) => user.organisationId === target.organisationId;
const isOwner = (user, target, ctx, action) => user.id === target.userId;

allow('ADMIN', ['manage'], Posts, isSameOrg);
allow('USER', ['edit*'], Posts, isOwner);

// Authorize access to a record, throws if not allowed
alsoCan.authorize(user, 'edit', record, ctx);
// Returns true if the user can perform the action
const can = alsoCan.can(user, 'edit', record, ctx);
```