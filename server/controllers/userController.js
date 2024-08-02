const jwt = require("jsonwebtoken");
const { expressjwt: exJwt } = require("express-jwt");

const bcrypt = require("bcrypt");
const Users = require("../models/register");

//ค้นหา user ทั้งหมด
exports.listUser = async (req, res) => {
  try {
    const user = await Users.find({}).select("-password").exec();
    res.json(user);
  } catch (error) {
    console.log("เกิดข้อผิดพลาด", error);
    res.status(400).json({ error: "Server isError" });
  }
};

//ค้นหา user แค่ 1  user
exports.readUser = async (req, res) => {
  try {
    const id = req.params.id;
    const user = await Users.find({ _id: id }).select("-password").exec();
    res.json(user);
  } catch (error) {
    // console.log("เกิดข้อผิดพลาด", error);
    res.status(400).json({ error: "Server isError" });
  }
};

// ค้นหา user 1 user และทำการ update
exports.updatePassword = async (req, res) => {
 
  try {
    const {id , password} = req.body.values
    // 1 gen salt
const  salt = await bcrypt.genSalt(10)
// encrypt 
const enPassword = await bcrypt.hash(password , salt)

const user = await Users.findOneAndUpdate(
  { _id: id },// ตัวที่ค้นหา
  { password: enPassword } // ตัวที่ต้องการให้ update

).exec();
res.json(user);
   
  } catch (error) {
    // console.log("เกิดข้อผิดพลาด", error);
    res.status(400).json({ error: "Server isError" });
  }
};

// ค้นหา user 1 user และทำการ delete

exports.deleteUser = async (req, res) => {
  try {
    const id = req.params.id;

    // { new: true } คือ การให้แสดงค่าใหม่
    await Users.findOneAndRemove({ _id: id }).exec();
    res.json({ message: "ทำการลบข้อมูลสำเร็จ" });
  } catch (error) {
    // console.log("เกิดข้อผิดพลาด", error);
    res.status(400).json({ error: "Server isError" });
  }
};

// ค้นหา user 1 user และทำการ update
exports.changStatus = async (req, res) => {
  try {
    console.log(req.body);
    const user = await Users.findOneAndUpdate(
      { _id: req.body.id },// ตัวที่ค้นหา
      { enabled: req.body.enabled } // ตัวที่ต้องการให้ update
    ).exec();
    res.json(user);
  } catch (error) {
    // console.log("เกิดข้อผิดพลาด", error);
    res.status(400).json({ error: "Server isError" });
  }
};

// ค้นหา user 1 user และทำการ update
exports.changeRole = async (req, res) => {
  console.log(req.body);
  try {
    const user = await Users.findOneAndUpdate(
      { _id: req.body.id },// ตัวที่ค้นหา
      { role: req.body.role } // ตัวที่ต้องการให้ update
    ).exec();
    res.json(user);
  } catch (error) {
    // console.log("เกิดข้อผิดพลาด", error);
    res.status(400).json({ error: "Server isError" });
  }
};



// update ข้อมูลฝั่ง Server
exports.resetPassword = async(req, res) => {
  try {
    const {id , password} = req.body.values
    // 1 gen salt
const  salt = await bcrypt.genSalt(10)
// encrypt 
const enPassword = await bcrypt.hash(password , salt)

const user = await Users.findOneAndUpdate(
  { _id: id },// ตัวที่ค้นหา
  { password: enPassword } // ตัวที่ต้องการให้ update

).exec();
res.json(user);
   
  } catch (error) {
    console.log("เกิดข้อผิดพลาด", error);
    res.status(400).json({ error: "Server isError" });
  }
};




exports.changeUser = async (req, res) => {
  try {
    console.log(req.body);
    const user = await Users.findOneAndUpdate(
      { _id: req.body.id },// ตัวที่ค้นหา
      { enabled: req.body.enabled } // ตัวที่ต้องการให้ update
    ).exec();
    res.json(user);
  } catch (error) {
    // console.log("เกิดข้อผิดพลาด", error);
    res.status(400).json({ error: "Server isError" });
  }
};