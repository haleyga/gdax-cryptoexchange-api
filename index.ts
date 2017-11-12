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
        'User-Agent'  : `GDAX API Client (gdax-cryptoexchange-api node package)`,
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
    [key: string]: string | number | boolean;
}

/**
 * The query string object shape.
 */
export interface IQueryParams {
    [key: string]: string | number | boolean;
}

export type IPaginationParams = { before?: string; after?: string, limit?: string };

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
export const signMessage = (privateKey: string, path: string, method: string, body?: IPostBody): ISignature => {

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

/**
 * Shape of signature object.
 */
export type ISignature = { digest: string; timestamp: number; };

/**
 * Convenient container for API keys.
 */
export type IApiAuth = { publicKey: string; privateKey: string; passphrase: string; };

/**
 * The shape of a raw request forwarding agent.
 */
export interface IRawAgent {
    auth?: IApiAuth;

    deleteFromPrivateEndpoint(endpoint: string, queryParams?: IQueryParams): Promise<IGdaxResponse>;

    isUpgraded(): boolean;

    getFromPrivateEndpoint(endpoint: string, queryParams?: IQueryParams): Promise<IGdaxResponse>;

    getPublicEndpoint(endpoint: string, queryParams?: IQueryParams): Promise<IGdaxResponse>;

    postToPrivateEndpoint(endpoint: string, data?: IPostBody): Promise<IGdaxResponse>;

    signMessage(privateKey: string, path: string, method: string, body?: IPostBody): ISignature;

    upgrade(newAuth: IApiAuth): void;
}

/**
 * Factory function to get a new GDAX client.
 *
 * @param {IApiAuth} auth
 * @returns {IRawAgent}
 */
const getRawAgent = (auth?: IApiAuth): IRawAgent => ({

    /**
     * This holds the user's API keys.
     */
    auth,

    /**
     * Deletes/removes/cancels from private (authenticated) endpoints.
     *
     * @param {string} endpoint
     * @param {IQueryParams} queryParams
     * @returns {Promise<IGdaxResponse>}
     */
    async deleteFromPrivateEndpoint(endpoint: string, queryParams?: IQueryParams): Promise<IGdaxResponse> {

        // Ensure the user has credentials
        if (!this.isUpgraded()) return Promise.reject(`api keys are required to access private endpoints`);

        // The uri is a relative path to the privateAgentConfig baseUrl
        const uri = `/${endpoint}?${qs.stringify(queryParams)}`;

        const signatureData = signMessage(this.auth.privateKey, uri, 'DELETE');

        // Add the appropriate POST request headers (Key and Sign)
        const headers = {
            ...privateAgentConfig.headers,
            'CB-ACCESS-KEY'       : this.auth.publicKey,
            'CB-ACCESS-PASSPHRASE': this.auth.passphrase,
            'CB-ACCESS-SIGN'      : signatureData.digest,
            'CB-ACCESS-TIMESTAMP' : signatureData.timestamp,
        };

        // Construct the actual config to be used
        const agentConfig = { ...privateAgentConfig, headers, method: 'DELETE', url: uri };

        try {
            const response = await axios(agentConfig);

            // Finally, send the request and return the response
            return Promise.resolve(response);
        } catch (err) {
            const rejectionReason = err.response.data.error || err.response.data || err.response || err;

            return Promise.reject(rejectionReason);
        }
    },

    /**
     * Fetches data from private (authenticated) endpoints.
     *
     * @param {string} endpoint
     * @param queryParams
     * @returns {Promise<IGdaxResponse>}
     */
    async getFromPrivateEndpoint(endpoint: string, queryParams?: IQueryParams): Promise<IGdaxResponse> {

        // Ensure the user has credentials
        if (!this.isUpgraded()) return Promise.reject(`api keys are required to access private endpoints`);

        // The uri is a relative path to the privateAgentConfig baseUrl
        const uri = `/${endpoint}?${qs.stringify(queryParams)}`;

        const signatureData = signMessage(this.auth.privateKey, uri, 'GET');

        // Add the appropriate POST request headers (Key and Sign)
        const headers = {
            ...privateAgentConfig.headers,
            'CB-ACCESS-KEY'       : this.auth.publicKey,
            'CB-ACCESS-PASSPHRASE': this.auth.passphrase,
            'CB-ACCESS-SIGN'      : signatureData.digest,
            'CB-ACCESS-TIMESTAMP' : signatureData.timestamp,
        };

        // Construct the actual config to be used
        const agentConfig = { ...privateAgentConfig, headers, method: 'GET', url: uri };

        try {
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
    async getPublicEndpoint(endpoint: string, queryParams?: IQueryParams): Promise<IGdaxResponse> {

        // The uri is a relative path to the publicAgentConfig baseUrl
        const uri = `/${endpoint}?${qs.stringify(queryParams)}`;

        // Construct the actual config to be used
        const agentConfig = { ...publicAgentConfig, url: uri };

        try {
            // Send the request.
            const response = await axios(agentConfig);

            // Finally, return the response
            return Promise.resolve(response);
        } catch (err) {
            const rejectionReason = err.response.data.error || err.response.data || err.response || err;

            return Promise.reject(rejectionReason);
        }
    },

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
     * Checks if the user has supplied API keys.
     *
     * @returns {boolean}
     */
    isUpgraded(): boolean { return this.auth; },

    /**
     * Upgrades a client with new credentials.
     *
     * @param {IApiAuth} newAuth
     */
    upgrade(newAuth: IApiAuth): void { this.auth = newAuth; },
});

export type INewOrderParams = {
    client_oid?: string,
    type?: string,
    side: string,
    product_id: string,
    stp?: string,
    price?: number,
    size?: number,
    time_in_force?: string,
    cancel_after?: string,
    post_only?: boolean,
    funds?: number,
    overdraft_enabled?: boolean,
    funding_amount?: number,
};

export type ICancelOrderParams = { product_id?: string };
export type IListOrdersParams = { status?: string[], product_id?: string };
export type IListFillsParams = { order_id?: string, product_id?: string };
export type IListFundingParams = { status?: string[] };
export type IRepayParams = { amount: number, currency: string };
export type ITransferMarginFundsParams = { margin_profile_id: string, type: string, currency: string, amount: number };
export type IClosePositionParams = { repay_only: boolean };
export type IDepositFromPaymentMethodParams = { amount: number, currency: string, payment_method_id: string };
export type IDepositFromCoinbaseAccountParams = { amount: number, currency: string, coinbase_account_id: string };
export type IWithdrawToPaymentMethodParams = { amount: number, currency: string, payment_method_id: string };
export type IWithdrawToCoinbaseAccountParams = { amount: number, currency: string, coinbase_account_id: string };
export type IWithdrawToCryptoAddressParams = { amount: number, currency: string, crypto_address: string };
export type ICreateReportParams = {
    type: string,
    start_date: string,
    end_date: string,
    product_id?: string,
    account_id?: string,
    format?: string,
    email?: string,
};

export type IGetProductOrderBookParams = { level: number };
export type IGetHistoricRatesParams = { start: string, end: string, granularity: number };

export interface IGdaxClient {
    rawAgent: IRawAgent;

    isUpgraded(): boolean;

    upgrade(auth: IApiAuth): void;

    getProducts(): Promise<IGdaxResponse>;

    getProductOrderBook(productId: string, bookParams?: IGetProductOrderBookParams): Promise<IGdaxResponse>;

    getProductTicker(productId: string): Promise<IGdaxResponse>;

    getTrades(productId: string, paginationParams?: IPaginationParams): Promise<IGdaxResponse>;

    getHistoricRates(productId: string, params: IGetHistoricRatesParams): Promise<IGdaxResponse>;

    get24HrStats(productId: string): Promise<IGdaxResponse>;

    getCurrencies(): Promise<IGdaxResponse>;

    getServerTime(): Promise<IGdaxResponse>;

    listAccounts(): Promise<IGdaxResponse>;

    getAccount(accountId: string): Promise<IGdaxResponse>;

    getAccountHistory(accountId: string, paginationParams?: IPaginationParams): Promise<IGdaxResponse>;

    getHolds(accountId: string, paginationParams?: IPaginationParams): Promise<IGdaxResponse>;

    placeNewOrder(params: INewOrderParams): Promise<IGdaxResponse>;

    cancelOrder(orderId: string): Promise<IGdaxResponse>;

    cancelAll(params?: ICancelOrderParams): Promise<IGdaxResponse>;

    listOrders(params?: IListOrdersParams, paginationParams?: IPaginationParams): Promise<IGdaxResponse>;

    getOrder(orderId: string): Promise<IGdaxResponse>;

    listFills(listFillsParams?: IListFillsParams, paginationParams?: IPaginationParams): Promise<IGdaxResponse>;

    listFunding(params?: IListFundingParams, paginationParams?: IPaginationParams): Promise<IGdaxResponse>;

    repay(params: IRepayParams): Promise<IGdaxResponse>;

    transferMarginFunds(params: ITransferMarginFundsParams): Promise<IGdaxResponse>;

    getPosition(): Promise<IGdaxResponse>;

    closePosition(closePositionParams?: IClosePositionParams): Promise<IGdaxResponse>;

    depositFromPaymentMethod(params: IDepositFromPaymentMethodParams): Promise<IGdaxResponse>;

    depositFromCoinbaseAccount(params: IDepositFromCoinbaseAccountParams): Promise<IGdaxResponse>;

    withdrawToPaymentMethod(params: IWithdrawToPaymentMethodParams): Promise<IGdaxResponse>;

    withdrawToCoinbaseAccount(params: IWithdrawToCoinbaseAccountParams): Promise<IGdaxResponse>;

    withdrawToCryptoAddress(params: IWithdrawToCryptoAddressParams): Promise<IGdaxResponse>;

    listPaymentMethods(): Promise<IGdaxResponse>;

    listCoinbaseAccounts(): Promise<IGdaxResponse>;

    createReport(params: ICreateReportParams): Promise<IGdaxResponse>;

    getReportStatus(reportId: string): Promise<IGdaxResponse>;

    getTrailingVolume(): Promise<IGdaxResponse>;
}

export const getClient = (auth?: IApiAuth): IGdaxClient => ({

    rawAgent: getRawAgent(auth),

    isUpgraded(): boolean { return this.rawAgent.isUpgraded(); },

    upgrade(newAuth: IApiAuth): void { this.rawAgent.upgrade(newAuth); },

    // Unauthenticated

    /**
     * Get a list of available currency pairs for trading.
     *
     * @returns {Promise<IGdaxResponse>}
     */
    async getProducts(): Promise<IGdaxResponse> {
        return this.rawAgent.getPublicEndpoint('products');
    },

    /**
     * Get a list of open orders for a product. The amount of detail shown can be customized with the level parameter.
     *
     * @param {string} productId
     * @param {IGetProductOrderBookParams} bookParams
     * @returns {Promise<IGdaxResponse>}
     */
    async getProductOrderBook(productId: string, bookParams?: IGetProductOrderBookParams): Promise<IGdaxResponse> {
        const params = bookParams || { level: 1 };

        return this.rawAgent.getPublicEndpoint(`products/${productId}/book`, params);
    },

    /**
     * Snapshot information about the last trade (tick), best bid/ask and 24h volume.
     *
     * @param {string} productId
     * @returns {Promise<IGdaxResponse>}
     */
    async getProductTicker(productId: string): Promise<IGdaxResponse> {
        return this.rawAgent.getPublicEndpoint(`products/${productId}/ticker`);
    },

    /**
     * List the latest trades for a product.
     *
     * @param {string} productId
     * @param {IPaginationParams} paginationParams
     * @returns {Promise<IGdaxResponse>}
     */
    async getTrades(productId: string, paginationParams?: IPaginationParams): Promise<IGdaxResponse> {
        return this.rawAgent.getPublicEndpoint(`products/${productId}/trades`, paginationParams);
    },

    /**
     * Historic rates for a product. Rates are returned in grouped buckets based on requested granularity.
     *
     * @param {string} productId
     * @param {IGetHistoricRatesParams} params
     * @returns {Promise<IGdaxResponse>}
     */
    async getHistoricRates(productId: string, params: IGetHistoricRatesParams): Promise<IGdaxResponse> {
        return this.rawAgent.getPublicEndpoint(`products/${productId}/candles`, params);
    },

    /**
     * Get 24 hr stats for the product. volume is in base currency units. open, high, low are in quote currency units.
     *
     * @param {string} productId
     * @returns {Promise<IGdaxResponse>}
     */
    async get24HrStats(productId: string): Promise<IGdaxResponse> {
        return this.rawAgent.getPublicEndpoint(`products/${productId}/stats`);
    },

    /**
     * List known currencies.
     *
     * @returns {Promise<IGdaxResponse>}
     */
    async getCurrencies(): Promise<IGdaxResponse> {
        return this.rawAgent.getPublicEndpoint('currencies');
    },

    /**
     * Get the API server time.
     *
     * @returns {Promise<IGdaxResponse>}
     */
    async getServerTime(): Promise<IGdaxResponse> {
        return this.rawAgent.getPublicEndpoint('time');
    },

    // Authenticated

    /**
     * Get a list of trading accounts.
     *
     * @returns {Promise<IGdaxResponse>}
     */
    async listAccounts(): Promise<IGdaxResponse> {
        return this.rawAgent.getFromPrivateEndpoint('accounts');
    },

    /**
     * Information for a single account. Use this endpoint when you know the account id.
     *
     * @param {string} accountId
     * @returns {Promise<IGdaxResponse>}
     */
    async getAccount(accountId: string): Promise<IGdaxResponse> {
        return this.rawAgent.getFromPrivateEndpoint(`accounts/${accountId}`);
    },

    /**
     * List account activity. Account activity either increases or decreases your account balance. Items are
     * paginated and sorted latest first. See the Pagination section for retrieving additional entries after the
     * first page.
     *
     * @param {string} accountId
     * @param paginationParams
     * @returns {Promise<IGdaxResponse>}
     */
    async getAccountHistory(accountId: string, paginationParams?: IPaginationParams): Promise<IGdaxResponse> {
        return this.rawAgent.getFromPrivateEndpoint(`accounts/${accountId}/ledger`, paginationParams);
    },

    /**
     * Holds are placed on an account for any active orders or pending withdraw requests. As an order is filled, the
     * hold amount is updated. If an order is canceled, any remaining hold is removed. For a withdraw, once it is
     * completed, the hold is removed.
     *
     * @param {string} accountId
     * @param {IPaginationParams} paginationParams
     * @returns {Promise<IGdaxResponse>}
     */
    async getHolds(accountId: string, paginationParams?: IPaginationParams): Promise<IGdaxResponse> {
        return this.rawAgent.getFromPrivateEndpoint(`accounts/${accountId}/holds`, paginationParams);
    },

    /**
     * You can place different types of orders: limit, market, and stop. Orders can only be placed if your account
     * has  sufficient funds. Once an order is placed, your account funds will be put on hold for the duration of
     * the  order. How much and which funds are put on hold depends on the order type and parameters specified. See
     * the  Holds details below.
     *
     * See https://docs.gdax.com/?#place-a-new-order for parameter details.  This library makes no attempt to verify
     * correct parameter usage.
     *
     * @param {INewOrderParams} params
     */
    async placeNewOrder(params: INewOrderParams): Promise<IGdaxResponse> {
        return this.rawAgent.postToPrivateEndpoint('orders', params);
    },

    /**
     * Cancel a previously placed order.
     *
     * If the order had no matches during its lifetime its record may be purged. This means the order details will not
     * be  available with GET /orders/<order-id>.
     *
     * @param {string} orderId
     * @returns {Promise<IGdaxResponse>}
     */
    async cancelOrder(orderId: string): Promise<IGdaxResponse> {
        return this.rawAgent.deleteFromPrivateEndpoint(`orders/${orderId}`);
    },

    /**
     * With best effort, cancel all open orders. The response is a list of ids of the canceled orders.
     *
     * @param {ICancelOrderParams} params
     * @returns {Promise<IGdaxResponse>}
     */
    async cancelAll(params?: ICancelOrderParams): Promise<IGdaxResponse> {
        return this.rawAgent.deleteFromPrivateEndpoint('orders', params);
    },

    /**
     * List your current open orders. Only open or un-settled orders are returned. As soon as an order is no longer
     * open and settled, it will no longer appear in the default request.
     *
     * @param {IListOrdersParams} params
     * @param paginationParams
     * @returns {Promise<IGdaxResponse>}
     */
    async listOrders(params?: IListOrdersParams, paginationParams?: IPaginationParams): Promise<IGdaxResponse> {

        // This endpoint allows multiple 'status' keys to be passed in the query string.  Since this is not
        // standard, we don't rely on the standard qs#stringify() from #getFromPrivateEndpoint.  Instead, we
        // construct the query string manually here and pass it as part of the endpoint - leaving the queryParams
        // empty.
        const statuses = [];

        if (params.status && params.status.constructor === Array) {
            for (const status of params.status) {
                statuses.push(`status=${status}`);
            }
        }

        const orderParams = params.product_id ?
                            `${statuses.join('&')}&product_id=${params.product_id}` :
                            `${statuses.join('&')}`;
        const pageParams  = qs.stringify(paginationParams);
        const queryString = [orderParams, pageParams].join('&');

        return this.rawAgent.getFromPrivateEndpoint(`orders?${queryString}`);
    },

    /**
     * Get a single order by order id.
     *
     * @param {string} orderId
     * @returns {Promise<void>}
     */
    async getOrder(orderId: string): Promise<IGdaxResponse> {
        return this.rawAgent.getFromPrivateEndpoint(`orders/${orderId}`);
    },

    /**
     * Get a list of recent fills.
     *
     * @param {IListFillsParams} listFillsParams
     * @param paginationParams
     * @returns {Promise<IGdaxResponse>}
     */
    async listFills(listFillsParams?: IListFillsParams, paginationParams?: IPaginationParams): Promise<IGdaxResponse> {
        const params = { ...listFillsParams, ...paginationParams };

        return this.rawAgent.getFromPrivateEndpoint('fills', params);
    },

    /**
     * @param {IListFundingParams} params
     * @param {IPaginationParams} paginationParams
     * @returns {Promise<IGdaxResponse>}
     */
    async listFunding(params?: IListFundingParams, paginationParams?: IPaginationParams): Promise<IGdaxResponse> {

        // This endpoint allows multiple 'status' keys to be passed in the query string.  Since this is not
        // standard, we don't rely on the standard qs#stringify() from #getFromPrivateEndpoint.  Instead, we
        // construct the query string manually here and pass it as part of the endpoint - leaving the queryParams
        // empty.
        const statuses = [];

        if (params.status && params.status.constructor === Array) {
            for (const status of params.status) {
                statuses.push(`status=${status}`);
            }
        }

        const fundingParams = `${statuses.join('&')}`;
        const pageParams    = qs.stringify(paginationParams);
        const queryString   = [fundingParams, pageParams].join('&');

        return this.rawAgent.getFromPrivateEndpoint(`funding?${queryString}`);
    },

    /**
     * Repay funding. Repays the older funding records first.
     *
     * @param {IRepayParams} params
     * @returns {Promise<IGdaxResponse>}
     */
    async repay(params: IRepayParams): Promise<IGdaxResponse> {
        return this.rawAgent.postToPrivateEndpoint('funding/repay', params);
    },

    /**
     * Transfer funds between your standard/default profile and a margin profile. A deposit will transfer funds from
     * the default profile into the margin profile. A withdraw will transfer funds from the margin profile to the
     * default profile. Withdraws will fail if they would set your margin ratio below the initial margin ratio
     * requirement.
     *
     * To get your margin profile id you can query GET /position with your margin profile’s API key.
     *
     * @param {ITransferMarginFundsParams} params
     * @returns {Promise<IGdaxResponse>}
     */
    async transferMarginFunds(params: ITransferMarginFundsParams): Promise<IGdaxResponse> {
        return this.rawAgent.postToPrivateEndpoint('profiles/margin-transfer', params);
    },

    /**
     * An overview of your profile.
     *
     * @returns {Promise<IGdaxResponse>}
     */
    async getPosition(): Promise<IGdaxResponse> {
        return this.rawAgent.getFromPrivateEndpoint('position');
    },

    /**
     * @param {IClosePositionParams} closePositionParams
     * @returns {Promise<IGdaxResponse>}
     */
    async closePosition(closePositionParams?: IClosePositionParams): Promise<IGdaxResponse> {
        const params = closePositionParams || { repay_only: false };

        return this.rawAgent.postToPrivateEndpoint('position/close', params);
    },

    /**
     * Deposit funds from a payment method. See the Payment Methods section for retrieving your payment methods.
     *
     * @param {IDepositFromPaymentMethodParams} params
     * @returns {Promise<IGdaxResponse>}
     */
    async depositFromPaymentMethod(params: IDepositFromPaymentMethodParams): Promise<IGdaxResponse> {
        return this.rawAgent.postToPrivateEndpoint('deposits/payment-method', params);
    },

    /**
     * Deposit funds from a coinbase account. You can move funds between your Coinbase accounts and your GDAX
     * trading accounts within your daily limits. Moving funds between Coinbase and GDAX is instant and free. See
     * the Coinbase Accounts section for retrieving your Coinbase accounts.
     *
     * @param {IDepositFromCoinbaseAccountParams} params
     * @returns {Promise<IGdaxResponse>}
     */
    async depositFromCoinbaseAccount(params: IDepositFromCoinbaseAccountParams): Promise<IGdaxResponse> {
        return this.rawAgent.postToPrivateEndpoint('deposits/coinbase-account', params);
    },

    /**
     * Withdraw funds to a payment method. See the Payment Methods section for retrieving your payment methods.
     *
     * @param {IWithdrawToPaymentMethodParams} params
     * @returns {Promise<IGdaxResponse>}
     */
    async withdrawToPaymentMethod(params: IWithdrawToPaymentMethodParams): Promise<IGdaxResponse> {
        return this.rawAgent.postToPrivateEndpoint('withdrawals/coinbase-account', params);
    },

    /**
     * Withdraw funds to a coinbase account. You can move funds between your Coinbase accounts and your GDAX trading
     * accounts within your daily limits. Moving funds between Coinbase and GDAX is instant and free. See the Coinbase
     * Accounts section for retrieving your Coinbase accounts.
     *
     * @param {IWithdrawToCoinbaseAccountParams} params
     * @returns {Promise<IGdaxResponse>}
     */
    async withdrawToCoinbaseAccount(params: IWithdrawToCoinbaseAccountParams): Promise<IGdaxResponse> {
        return this.rawAgent.postToPrivateEndpoint('withdrawals/coinbase-account', params);
    },

    /**
     * Withdraws funds to a crypto address.
     *
     * @param {IWithdrawToCryptoAddressParams} params
     * @returns {Promise<IGdaxResponse>}
     */
    async withdrawToCryptoAddress(params: IWithdrawToCryptoAddressParams): Promise<IGdaxResponse> {
        return this.rawAgent.postToPrivateEndpoint('withdrawals/crypto', params);
    },

    /**
     * Get a list of your payment methods.
     *
     * @returns {Promise<IGdaxResponse>}
     */
    async listPaymentMethods(): Promise<IGdaxResponse> {
        return this.rawAgent.getFromPrivateEndpoint('payment-methods');
    },

    /**
     * Get a list of your coinbase accounts.
     *
     * Visit the Coinbase accounts API for more information.
     *
     * @returns {Promise<IGdaxResponse>}
     */
    async listCoinbaseAccounts(): Promise<IGdaxResponse> {
        return this.rawAgent.getFromPrivateEndpoint('coinbase-accounts');
    },

    /**
     * Reports provide batches of historic information about your account in various human and machine readable forms.
     *
     * @param {ICreateReportParams} params
     * @returns {Promise<IGdaxResponse>}
     */
    async createReport(params: ICreateReportParams): Promise<IGdaxResponse> {
        return this.rawAgent.postToPrivateEndpoint('reports', params);
    },

    /**
     * @param {string} reportId
     * @returns {Promise<IGdaxResponse>}
     */
    async getReportStatus(reportId: string): Promise<IGdaxResponse> {
        return this.rawAgent.getFromPrivateEndpoint(`reports/${reportId}`);
    },

    /**
     * This request will return your 30-day trailing volume for all products. This is a cached value that’s
     * calculated every day at midnight UTC.
     *
     * @returns {Promise<IGdaxResponse>}
     */
    async getTrailingVolume(): Promise<IGdaxResponse> {
        return this.rawAgent.getFromPrivateEndpoint('users/self/trailing-volume');
    },
});

/**
 * Alias for Axios request options.
 */
export interface IGdaxRequestConfig extends AxiosRequestConfig {}

/**
 * Alias for Axios response.
 */
export interface IGdaxResponse extends AxiosResponse {}
