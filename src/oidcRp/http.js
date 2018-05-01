var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;

class HttpRequest {
    constructor(){
    }

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