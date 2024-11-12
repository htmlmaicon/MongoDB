const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  id: { type: String, unique: true, required: true },
  title: { type: String, required: true },
  price: { type: Number, required: true },
  description: { type: String, required: false },
  thumbnail: { type: String, required: true },
});

module.exports = mongoose.model('Product', productSchema);
