const mongoose = require("mongoose");


const messageIdSchema = mongoose.Schema({
    messageId: String,

});

const messageId = mongoose.model("messageId", messageIdSchema);

module.exports = messageId;
