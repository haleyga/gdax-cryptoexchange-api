import * as axiosDefault from 'axios';
import { AxiosRequestConfig, AxiosResponse } from 'axios';
import * as crypto from 'crypto';
import * as qs from 'qs';

/**
 * Just an alias.
 */
const axios = axiosDefault.default;

/**
 * Default configuration.
 */
const defaultConfig = {
    rootUrl: `https://api.gdax.com`,
    timeout: 10000,
};

/**
 * Default HTTP agent configuration.
 */
const defaultAgentConfig = {
    baseURL: defaultConfig.rootUrl,
    headers: {
        'Content-Type': 'application/json',
        'User-Agent'  : `GDAX API Client (gdax-api node package)`,
    },
    method : 'GET',
    timeout: defaultConfig.timeout,
};

/**
 * The public agent is essentially an alias for the default configuration.
 *
 * @type {{}}
 */
const publicAgentConfig = {
    ...defaultAgentConfig,
};

/**
 * The private agent begins life the same as the public agent, but with 'POST' specified.
 *
 * @type {{method: string}}
 */
const privateAgentConfig = {
    ...defaultAgentConfig,
    method: 'POST',
};

/**
 * The post body shape.
 */
export interface IPostBody {
    [key: string]: string | number;
}

/**
 * This function is exported so that a user can experiment with/understand how GDAX wants requests to be signed.
 * Essentially, for user edification ;).
 *
 * @param {string} privateKey
 * @param {string} path
 * @param method
 * @param {{}} body
 * @returns {ISignature}
 */
export const signMessage = (privateKey: string, path: string, method: string, body?: {}): ISignature => {

    //tslint:disable:no-magic-numbers
    const timestamp = Date.now() / 1000;
    //tslint:enable:no-magic-numbers

    // Decrypt the private key.
    const key = new Buffer(privateKey, 'base64');

    // Create the hmac.
    const hmac = crypto.createHmac('sha256', key);

    // Build a string to hash.
    const prehash = body ?
                    `${timestamp}${method.toUpperCase()}${path}${JSON.stringify(body)}` :
                    `${timestamp}${method.toUpperCase()}${path}`;

    // Generate the hmac digest in base64.
    const digest = hmac.update(prehash).digest('base64');

    // Return the digest and the timestamp used in the hmac hash.
    return { digest, timestamp };
};

export interface ISignature {
    digest: string;
    timestamp: number;
}

/**
 * Convenient container for API keys.
 */
export interface IApiAuth {
    publicKey: string;
    privateKey: string;
    passphrase: string;
}

/**
 * The shape of a GDAX client.
 */
export interface IGdaxClient {
    auth?: IApiAuth;

    isUpgraded(): boolean;

    getFromPrivateEndpoint(endpoint: string, data?: IPostBody): Promise<IGdaxResponse>;

    getPublicEndpoint(endpoint: string, queryParams?: {}): Promise<IGdaxResponse>;

    postToPrivateEndpoint(endpoint: string, data?: IPostBody): Promise<IGdaxResponse>;

    signMessage(privateKey: string, path: string, method: string, body?: {}): ISignature;

    upgrade(newAuth: IApiAuth): void;
}

/**
 * Factory function to get a new GDAX client.
 *
 * @param {IApiAuth} auth
 * @returns {IGdaxClient}
 */
export const getClient = (auth?: IApiAuth): IGdaxClient => ({

    /**
     * This holds the user's API keys.
     */
    auth,

    /**
     * Fetches data from private (authenticated) endpoints.
     *
     * @param {string} endpoint
     * @param {IPostBody} data
     * @returns {Promise<IGdaxResponse>}
     */
    async getFromPrivateEndpoint(endpoint: string, data?: IPostBody): Promise<IGdaxResponse> {

        // Ensure the user has credentials
        if (!this.isUpgraded()) return Promise.reject(`api keys are required to access private endpoints`);

        // The uri is a relative path to the privateAgentConfig baseUrl
        const uri = `/${endpoint}`;

        const signatureData = signMessage(this.auth.privateKey, uri, 'GET', data);

        // Add the appropriate POST request headers (Key and Sign)
        const headers = {
            ...privateAgentConfig.headers,
            'CB-ACCESS-KEY'       : this.auth.publicKey,
            'CB-ACCESS-PASSPHRASE': this.auth.passphrase,
            'CB-ACCESS-SIGN'      : signatureData.digest,
            'CB-ACCESS-TIMESTAMP' : signatureData.timestamp,
        };

        // Construct the actual config to be used
        const agentConfig = { ...privateAgentConfig, headers, method: 'GET', url: uri, data: qs.stringify(data) };

        try {
            console.log(agentConfig);
            const response = await axios(agentConfig);

            // Finally, send the request and return the response
            return Promise.resolve(response);
        } catch (err) {
            const rejectionReason = err.response.data.error || err.response.data || err.response || err;

            return Promise.reject(rejectionReason);
        }
    },

    /**
     * Fetches data from public (unauthenticated) endpoints.
     *
     * @param {string} endpoint
     * @param {{}} queryParams
     * @returns {Promise<IGdaxResponse>}
     */
    async getPublicEndpoint(endpoint: string, queryParams?: {}): Promise<IGdaxResponse> {

        // The uri is a relative path to the publicAgentConfig,baseUrl
        const uri = `/${endpoint}?${qs.stringify(queryParams)}`;

        // Construct the actual config to be used
        const agentConfig = { ...publicAgentConfig, url: uri };

        // Send the request.
        const response = await axios(agentConfig);

        // Finally, return the response
        return Promise.resolve(response);
    },

    /**
     * Checks if the user has supplied API keys.
     *
     * @returns {boolean}
     */
    isUpgraded(): boolean { return this.auth; },

    /**
     * Posts to private (authenticated) endpoints.  If no API keys have been provided, this function will fail.
     *
     * @param {string} endpoint
     * @param {IPostBody} data
     * @returns {Promise<IGdaxResponse>}
     */
    async postToPrivateEndpoint(endpoint: string, data?: IPostBody): Promise<IGdaxResponse> {

        // Ensure the user has credentials
        if (!this.isUpgraded()) return Promise.reject(`api keys are required to access private endpoints`);

        // The uri is a relative path to the privateAgentConfig baseUrl
        const uri = `/${endpoint}`;

        const signatureData = signMessage(this.auth.privateKey, uri, 'POST', data);

        // Add the appropriate POST request headers (Key and Sign)
        const headers = {
            ...privateAgentConfig.headers,
            'CB-ACCESS-KEY'       : this.auth.publicKey,
            'CB-ACCESS-PASSPHRASE': this.auth.passphrase,
            'CB-ACCESS-SIGN'      : signatureData.digest,
            'CB-ACCESS-TIMESTAMP' : signatureData.timestamp,
        };

        // Construct the actual config to be used
        const agentConfig = { ...privateAgentConfig, headers, url: uri, data };

        try {
            console.log(agentConfig);
            const response = await axios(agentConfig);

            // Finally, send the request and return the response
            return Promise.resolve(response);
        } catch (err) {
            const rejectionReason = err.response.data.error || err.response.data || err.response || err;

            return Promise.reject(rejectionReason);
        }
    },

    /**
     * Include the exported #signMessage function for convenience.
     */
    signMessage,

    /**
     * Upgrades a client with new credentials.
     *
     * @param {IApiAuth} newAuth
     */
    upgrade(newAuth: IApiAuth): void { this.auth = newAuth; },
});

/**
 * Alias for Axios request options.
 */
export interface IGdaxRequestConfig extends AxiosRequestConfig {}

/**
 * Alias for Axios response.
 */
export interface IGdaxResponse extends AxiosResponse {}
