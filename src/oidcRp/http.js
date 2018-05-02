var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;

/**
 * HttpRequest
 * @class 
 * @constructor 
 */
class HttpRequest {
    constructor(){
    }

    /** 
     * Send a HTTP request to a URL using a specified method and returns a callback
     * @param {string} theUrl 
     * @param {function} callback 
     * @param {Object<string, string>} data 
     */ 
    httpGetAsync(theUrl, callback, data)
    {
        var xmlHttp = new XMLHttpRequest();
        xmlHttp.onreadystatechange = function() { 
            if (xmlHttp.readyState == 4 && xmlHttp.status == 200)
                callback(xmlHttp);
        }
        xmlHttp.open("GET", theUrl, false); // true for asynchronous 
        xmlHttp.setRequestHeader('Content-type', data.headers['Content-Type']);
        xmlHttp.setRequestHeader('Authorization', data.headers['Authorization']); 
        xmlHttp.send(data.body);
    }
}

module.exports.HttpRequest = HttpRequest;