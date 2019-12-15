const colors = require('colors');

/* eslint-disable no-use-before-define */

function defaultUser(user) { return user; }

function modelCompare(instance, model) {
	if (model === 'all') return true;
	if ((typeof model !== 'string') && (instance instanceof model)) return true;
	return instance === model;
}

const targetCompare = modelCompare;
const userCompare = modelCompare;

function actionCompare(action, abilityAction) {
	if (abilityAction === 'manage' || abilityAction === 'ALL') return true;
	if (abilityAction === action) return true;

	if (abilityAction instanceof RegExp) {
		return abilityAction.test(action);
	}

	return false;
}

function createError(user, action, record, message, extra) {
	// eslint-disable-next-line no-param-reassign
	message = message || 'You are not authorized to do that.';

	const options = {
		action,
		model: toString(record),
		user: toString(user),
		extra,
	};

	if (user.token) options.roles = user.token.roles;

	return new AuthorizationError(message, options);
}

function validateAllow(args) {
	if (args.length > 3 && !args[3]) {
		throw new Error(`It looks like you passed 'undefined' instead of a function to the third argument to allow (arguments: ${args}). (passing 'undefined' will grant permission unconditionally, which is probably not what you want)`);
	}
	const names = ['user', 'action', 'model'];

	args.forEach((arg, i) => {
		const a = Array.isArray(arg) ? arg : [arg];
		a.forEach((argument) => {
			if (!argument) throw new Error(`undefined passed into allow (${arg}). (user: ${args[0]}, action: ${args[1]}, model: ${args[2]})`);
			if (Array.isArray(argument)) throw new Error(`nested array passed into allow (${names[i]} argument), make sure you flatten the argument (user: ${args[0]}, action: ${args[1]}, model: ${args[2]})`);
		});
	});
}

class AlsoCan {
	/**
	  * @param {function} options.defaultUser fn(user)
	  * @param {function} options.userCompare fn(currentUser, abilityUser)
	  * @param {function} options.targetCompare fn(currentTarget, abilityTarget)
	  * @param {function} options.actionCompare fn(currentAction, abilityAction)
	  * @param {function} options.createError fn(user, action, record, condition)
	  */
	constructor(options) {
		// Save options to this, but don't clobber the debug function
		Object.assign(this, {
			defaultUser,
			userCompare,
			targetCompare,
			actionCompare,
			createError,
		}, options);

		this.options = options;

		this.listeners = {};
		this.abilities = [];

		['authorize', 'can', 'allow', 'deny'].forEach((fn) => {
			this[fn] = this[fn].bind(this);
		});
	}

	on(name, fn) {
		if (!this.listeners[name]) this.listeners[name] = [];
		if (this.listeners[name].find(fn)) throw new Error(`Function ${fn.name} already registered for event ${event}`);
		this.listeners[name].push(fn);
	}

	emit(event, ...args) {
		if (this.listeners[event]) {
			this.listeners[event].forEach(fn => fn(...args));
		}
	}

	setAbilities(abilities) {
		this.abilities = abilities.map(a => new Ability(this, a));
	}

	getAbilities() {
		return this.abilities;
	}

	allow(user, action, target, condition) {
		// eslint-disable-next-line prefer-rest-params
		validateAllow(arguments);
		this.abilities.push(new Ability(this, { user, action, target, condition }));
	}

	deny(user, action, target, condition) {
		// eslint-disable-next-line prefer-rest-params
		validateAllow(arguments);
		this.abilities.push(new Ability(this, { user, action, target, condition, deny: true }));
	}

	authorize(user, action, target, ctx) {
		const performer = this.defaultUser(user);
		const isAuthorized = this.can(performer, action, target, ctx);

		if (!isAuthorized) {
			const denied = (isAuthorized === false);
			throw this.createError(performer, action, target, null, { denied });
		}
	}

	can(user, action, target, ctx, options) {
		const performer = this.defaultUser(user);

		if (this.debug) debugHeader(performer, action, target, options);

		for (let i = 0; i < this.abilities.length; i++) {
			const ability = this.abilities[i];

			const isAuthorized = ability.can(performer, action, target, ctx, options);

			// if it is true, it's allowed, stop checking
			// if it is === false then it's explicitly denied, stop immediately
			if (isAuthorized === false || isAuthorized) {
				if (this.debug) debugFooter(this, isAuthorized);
				return isAuthorized;
			}
		}
		if (this.debug) debugFooter(this, null);

		return null;
	}

	/**
	  * Return a subset of the abilities for which user matches
	  * @param {object} user The same user you would pass to can or authorize
	  * @returns {object[]} Array of abilities matching that user
	  */
	getUserAbilities(user) {
		return this.abilities
			.filter(ability => ability.userCompare(user, ability.user))
			.map(ability => ability.toJSON());
	}

	/**
	  * Return a subset of the abilities for which a target matches
	  * @param {string|RegExp} target String or regexp to match the target name
	  * @returns {object[]} Array of abilities matching that user
	  */
	 getTargetAbilities(target) {
		return this.abilities
			.filter(ability => (Array.isArray(ability.target) ?
				ability.target.find(t => matchTarget(targetName(t), target)) :
				matchTarget(targetName(ability.target), target))
			)
			.map(ability => ability.toJSON())
			.map((ability) => {
				if (Array.isArray(ability.target)) {
					ability.target = ability.target.filter(t => matchTarget(t, target));
				}
				return ability;
			});
	}
}

function matchTarget(abilityTarget, targetMatch) {
	return (abilityTarget === 'all') ||
		((targetMatch instanceof RegExp) ?
			targetMatch.test(abilityTarget) : targetMatch === abilityTarget);
}

function targetName(target) {
	if (typeof target === 'string') return target;
	return target.$MockModel || target.name;
}

function singleAbility(fn) {
	return function matchSingleAbility(instance, toMatch, options = {}, ...args) {
		const match = fn(instance, toMatch, ...args);
		return match && options.describeMatch ? [toMatch] : !!match;
	};
}

function arrayAbility(fn) {
	return function matchArrayAbility(instance, toMatch, options = {}, ...args) {
		const matcher = ability => fn(instance, ability, ...args);

		if (options.describeMatch) {
			const matches = toMatch.filter(matcher);
			return matches.length ? matches : false;
		}
		return !!toMatch.find(matcher);
	};
}

class Ability {
	/**
	  * @param {AlsoCan} alsoCan alsoCan instance
	  * @param {object} config.user
	  * @param {string} config.action
	  * @param {object} config.target
	  */
	constructor(alsoCan, config) {
		Object.assign(this, config);

		this.alsoCan = alsoCan;

		// If action includes wildcards, turn them into regex's for easy
		// matching at runtime
		if (this.action.includes('*')) {
			this.action = this.action.replace(/\*/g, '.*');
			this.action = new RegExp(`${this.action}`);
		}

		// Set up shortcuts to this.userCompare, etc
		// If the ability is an array, then set up an array matcher for that
		// ability
		['user', 'action', 'target'].forEach((type) => {
			const fnName = `${type}Compare`;
			this[fnName] = Array.isArray(config[type]) ?
				arrayAbility(alsoCan[fnName]) : 
				singleAbility(alsoCan[fnName]);
		});
	}

	/**
	  * @returns {boolean} true if this ability matches
	  * @see #can
	  * @note does not check if this is a deny rule, see #can to determine
	  * if this rule allows
	  */
	matches(user, action, target, ctx, options = {}) {
		const isRole = colors.green('yes');
		const isAction = this.action === 'manage' ? colors.yellow('manage') : colors.green(' yes  ');
		const isTarget = this.target === 'all' ? colors.yellow('(all)') : colors.green('yes');
		const no = colors.red('no');
		let debugStr = `is ${toString(this.user)}`;

		const match = {};
		let usersToMatch = this.user;
		if (options.excludeUsers) {
			if (Array.isArray(this.user)) {
				usersToMatch = this.user.filter(u => !options.excludeUsers.includes(u));
			} else {
				usersToMatch = options.excludeUsers.includes(this.user) ? '__do_not_match__' : this.user;
			}
		}

		match.user = this.user === 'all' ? ['ALL'] : this.userCompare(user, usersToMatch, options);

		if (!match.user) {
			if (this.alsoCan.debug === 'FULL') console.log(`${debugStr} ${no}`);
			return false;
		}
		debugStr += ` ${isRole} can ${action}`;

		match.action = this.action === 'manage' ? 'manage' : this.actionCompare(action, this.action, options);

		if (!match.action) {
			if (this.alsoCan.debug) console.log(`${debugStr} ${no}`);
			return false;
		}

		if (this.alsoCan.debug) {
			const targetStr = Array.isArray(this.target) ?
				this.target.map(t => t.name) : this.target.name;
			debugStr += ` ${isAction} on ${targetStr}`;
		}

		match.target = this.target === 'all' ? ['all'] : this.targetCompare(target, this.target, options);

		if (!match.target) {
			if (this.alsoCan.debug) console.log(`${debugStr} ${no}`);
			return false;
		}

		debugStr += ` ${isTarget}`;

		if (this.condition) {
			match.condition = this.condition.name;
			const conditionIsFunction = typeof this.condition === 'function';
			if (conditionIsFunction && !this.condition(user, target, ctx, action)) {
				if (this.alsoCan.debug) console.log(`${debugStr} (${match.condition} ${no})`);
				return false;
			}

			debugStr += `(${match.condition})`;
		}

		if (this.alsoCan.debug) {
			let authorized = colors.green('* GRANT *');
			if (this.deny) {
				match.deny = true;
				authorized = colors.red('* DENIED *');
			}
			console.log(`${debugStr} ${authorized}`);
		}
		return match;
	}

	/**
	  * Checks if this rule is a match, and if the ability should be allowed/disallowed
	  * @param {boolean} options.describeMatch if true, will return an object describing the match (even if deny)
	  * @warning If describeMatch is true, then you must examine the return value as it could be truthy
	  * but contain { deny: true }
	  * @returns {boolean} false if it is a deny rule, null for no match, true for allow
	  */
	can(user, action, target, ctx, options = {}) {
		const match = this.matches(user, action, target, ctx, options);
		if (match) {
			return options.describeMatch ? match : !this.deny;
		}
		return null;
	}

	toString() {
		const can = this.deny ? 'CANNOT' : 'can';
		const condition = this.condition ? ` if ${this.condition.name}` : '';
		return `${this.user} ${can} ${this.action} ${this.target}${condition}`;
	}

	toJSON() {
		return {
			user: this.user,
			action: this.action,
			target: Array.isArray(this.target) ?
				this.target.map(t => targetName(t)) :
				targetName(this.target),
			condition: this.condition && this.condition.name,
			deny: this.deny,
		};
	}
}

function debugHeader(user, action, target, options = {}) {
	let targetObj = target;

	if (Array.isArray(target) && target.length) targetObj = targetObj[0];

	let question = `Can ${toString(user)} ${action} `;
	if (Array.isArray(target)) question += '(array of) ';
	question += toString(targetObj);

	const authType = options.describeMatch ? '(match description requested)' : '';

	console.log(`Debug Authorisation: ${authType}`);
	console.log(question);
	console.log('====');
}

function debugFooter(alsoCan, result) {
	let outcome = 'not found';
	if (result === false) outcome = 'DENIED';
	if (result) outcome = 'GRANTED';

	console.log(`Authorization? ${outcome}`);

	if (alsoCan.debug !== 'FULL') {
		console.log('(Some were not shown because user does not match, set alsoCan.debug = \'FULL\' to show)');
	}
}

function toString(x) {
	return (x && x.toString()) || '(null)';
}

class AuthorizationError extends Error {
	constructor(message, details) {
		super();
		this.name = 'AuthorizationError';

		this.message = message;
		this.details = details;
		Object.assign(this, details);
	}
}

Object.assign(AlsoCan, {
	AuthorizationError,
});

module.exports = AlsoCan;