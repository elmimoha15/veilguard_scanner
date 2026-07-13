const Stripe = require('stripe');

// Hardcoded secret key passed directly to the SDK constructor.
const stripe = new Stripe('sk_live_51QabcdEFGH1234567890ijklMNOPqrstUVWXyz');

module.exports = { stripe };
