/*
Copyright (c) Microsoft Corporation. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use these files except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
*/

/*
This file implements a polyfill that maps current Web Authentication API on
top of the Microsoft Edge preliminary implementation.
It is available for Edge 14 and above.

The polyfill is up-to-date with the Editor's Draft of Sept 28th. Please refer
to this link for the spec: http://www.w3.org/TR/2016/WD-webauthn-20160928/

This implementation inherits its limitations on parameter values from the
Edge implementation.

Notes on limitations:
The polyfill only works if the user has created a PIN (and optionally Hello
gestures) for themselves in Settings->Accounts->Sign-in options. Otherwise,
a error will be thrown.

makeCredential:
	- the attestationChallenge parameter is ignored
	- the options parameter ignored, including timeOutSeconds, rpId, and excludeList
	- the returned signature is different between the current Web Authentication API
	  and the polyfill

getAssertion:
 	- two parameters of the option parameter, timeoutSeconds and rpId, are ignored
 	- the returned signature is different between the current Web Authentication API
    and the polyfill
*/

/* global msCredentials */
navigator.authentication = navigator.authentication || (function () {
	'use strict';

	const webauthnDB = (function () {
		const WEBAUTHN_DB_VERSION = 1;
		const WEBAUTHN_DB_NAME = '_webauthn';
		const WEBAUTHN_ID_TABLE = 'identities';

		let db = null;
		let initPromise = null;

		const initDB = function () {
	 /* to remove database, use window.indexedDB.deleteDatabase('_webauthn'); */
			return new Promise((resolve, reject) => {
				const req = indexedDB.open(WEBAUTHN_DB_NAME, WEBAUTHN_DB_VERSION);
				req.onupgradeneeded = function() {
					// new database - set up store
					db = req.result;
					db.createObjectStore(WEBAUTHN_ID_TABLE, { keyPath: 'id'});
				};

				req.onsuccess = function() {
					db = req.result;
					resolve();
				};

				req.onerror = function(e) {
					reject(e);
				};
			});
		};

		const doStore = function (id, data) {
			if (!db) {
				throw new Error('UnknownError');
			}
			return new Promise((resolve, reject) => {
				const tx = db.transaction(WEBAUTHN_ID_TABLE, 'readwrite');
				const store = tx.objectStore(WEBAUTHN_ID_TABLE);
				store.put({id, data});

				tx.oncomplete = function() {
					resolve();
				};

				tx.onerror = function(e) {
					reject(e);
				};
			});
		};

		const store = function (id, data) {
			if (!initPromise) {
				initPromise = initDB();
			}
			return initPromise.then(() => {
				return doStore(id, data);
			});
		};

		const doGetAll = function () {
			if (!db) {
				throw new Error('UnknownError');
			}

			return new Promise((resolve, reject) => {
				const tx = db.transaction(WEBAUTHN_ID_TABLE, 'readonly');
				const req = tx.objectStore(WEBAUTHN_ID_TABLE).openCursor();
				const res = [];

				req.onsuccess = function() {
					const cur = req.result;
					if (cur) {
						res.push({id: cur.value.id, data: cur.value.data});
						cur.continue();
					} else {
						resolve(res);
					}
				};

				req.onerror = function(e) {
					reject(e);
				};
			});
		};

		const getAll = function () {
			if (!initPromise) {
				initPromise = initDB();
			}
			return initPromise.then(doGetAll);
		};


		return {
			store,
			getAll
		};
	}());


	const makeCredential = function (accountInfo, cryptoParams) {
		try {
			/* Need to know the display name of the relying party, the display name
			   of the user, and the user id to create a credential. For every user
			   id, there is one credential stored by the authenticator. */
			const acct = {
				rpDisplayName: accountInfo.rpDisplayName,
				userDisplayName: accountInfo.displayName,
				userId: accountInfo.id
			};
			const params = [];

			if (accountInfo.name) {
				acct.accountName = accountInfo.name;
			}
			if (accountInfo.imageUri) {
				acct.accountImageUri = accountInfo.imageUri;
			}

			for (const cryptoParam of cryptoParams) {
				// The type identifier used to be 'FIDO_2_0' instead of 'ScopedCred'
				if (cryptoParam.type === 'ScopedCred') {
					params.push({ type: 'FIDO_2_0', algorithm: cryptoParam.algorithm });
				} else {
					params.push(cryptoParam);
				}
			}

			return msCredentials.makeCredential(acct, params)
				.then((cred) => {
					if (cred.type === 'FIDO_2_0') {
					// The returned credential should be immutable, aka freezed.
						const result = Object.freeze({
							credential: {type: 'ScopedCred', id: cred.id},
							publicKey: JSON.parse(cred.publicKey),
							attestation: cred.attestation
						});

						return webauthnDB.store(result.credential.id, accountInfo).then(() => {
							return result;
						});
					}

					return cred;
				})
				.catch((err) => {
					console.log(`makeCredential failed: ${err}`);
					throw new Error('NotAllowedError');
				});
		} catch (err) {
			throw new Error('NotAllowedError');
		}
	};


	const getCredList = function (allowlist) {
		/* According to the spec, if allowList is supplied, the credentialList
		   comes from the allowList; otherwise the credentialList is from searching all
		   previously stored valid credentials. */
		if (allowlist) {
			return Promise.resolve(allowlist.map((descriptor) => {
				if (descriptor.type === 'ScopedCred') {
					return { type: 'FIDO_2_0', id: descriptor.id};
				}
				return descriptor;
			}));
		}
		webauthnDB.getAll()
			.then((list) => {
				return Promise.resolve(list.map((descriptor) => {
					return { type: 'FIDO_2_0', id: descriptor.id};
				}));
			})
			.catch((err) => {
				console.log(`Credential lists cannot be retrieved: ${err}`);
			});
	};


	const getAssertion = function (challenge, options) {
		let allowlist;
		try {
			 allowlist = options ? options.allowList : void 0;
		} catch (e) {
			throw new Error('NotAllowedError');
		}

		return getCredList(allowlist).then((credList) => {
			const filter = { accept: credList };
			let sigParams;

			if (options && options.extensions && options.extensions.webauthn_txAuthSimple) {
				sigParams = { userPrompt: options.extensions.webauthn_txAuthSimple };
			}

			return msCredentials.getAssertion(challenge, filter, sigParams);
		})
			.then((sig) => {
				if (sig.type === 'FIDO_2_0') {
					return Promise.resolve(Object.freeze({

						credential: {type: 'ScopedCred', id: sig.id},
						clientData: sig.signature.clientData,
						authenticatorData: sig.signature.authnrData,
						signature: sig.signature.signature

					}));
				}

				return Promise.resolve(sig);
			})
			.catch((err) => {
				console.log(`getAssertion failed: ${err}`);
				throw new Error('NotAllowedError');
			});
	};


	return {
		makeCredential,
		getAssertion
	};
}());
