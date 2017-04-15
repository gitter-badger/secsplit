// Node imports


// External imports


// Internal imports


// Constants


// Application
function validate(schema, object) {
    return schema.every((element) => {
        // If required, return false if not present
        if(element.required && typeof object[element.name] === 'undefined') {
            return false;
        }
        // Pass into the validator if it exists. Otherwise, mark it as passed
        if(typeof element.validator !== 'function') {
            return true;
        } else {
            return element.validator(object[element.name], object);
        }
    });
}


// Exports
module.exports = validate;
