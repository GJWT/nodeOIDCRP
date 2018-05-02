module.exports = {
    "env": {
        "es6": true,
        "node": true,
	"mocha":true,
    },
    "extends": ["eslint:recommended"],
    "parserOptions": {
        "ecmaVersion":6,
    },
    "rules": {
	"no-shadow": "error",
	"eqeqeq": "error",
        "indent": [
            "error",
            2
        ],
        "quotes": [
            "error",
            "single"
        ],
        "semi": [
            "error",
            "always"
        ]
    }
};
