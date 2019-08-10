const request = require('request');
const util = require('util');
const getPromise = util.promisify(request.get);

module.exports = {
    async httpGetJson(url, auth) {
        try {
            let result;
            if (auth) {
                result = await getPromise(url);
            } else {
                result = await getPromise(url);
            }
            return JSON.parse(result.body);
        } catch (e) {
            console.error(e);
            return false;
        }
    }
};