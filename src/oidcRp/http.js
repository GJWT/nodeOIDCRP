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
        ///xmlHttp.open("POST", theUrl, false); // true for asynchronous 
        //xmlHttp.send(null);
        //xmlHttp.setRequestHeader('Content-type', data.headers['Content-Type']);
        //xmlHttp.setRequestHeader('Authorization', data.headers['Authorization']); 
        //xmlHttp.send(data.body);
        //xmlHttp.send('grant_type=authorization_code&redirect_uri=https%3A%2F%2Fexample.com%2Frp%2Fauthz_cb%2Fgithub&client_id=eeeeeeeee&state=yWlhPdCQbZG7b8Dc9j9Hxl5ki7zL6Zaj&code=access_code&client_secret=aaaaaaaaaaaaa');
    }
}

module.exports.HttpRequest = HttpRequest;