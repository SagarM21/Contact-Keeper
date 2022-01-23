const express = require("express");
const router = express.Router();
const User = require("../models/User");
const { check, validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

// @route GET api/auth
// @desc Get logged in user
// @access Private
router.get("/", (req, res) => {
	res.send("Get logged in user");
});

// @route POST api/auth
// @desc Login user & auth token
// @access Public
router.post(
	"/",
	[
		check("email", "Please enter a email").isEmail(),
		check("password", "Please include a password").exists(),
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}

		const { email, password } = req.body;
		try {
			let user = await User.findOne({ email });
			if (!user) {
				return res.status(400).json({ msg: "Invalid credentials" });
			}
			const isMatch = await bcrypt.compare(password, user.password);
			if (!isMatch) {
				return res.status(400).json({ msg: "Invalid credentails" });
			}

			const payload = {
				user: {
					id: user.id,
				},
			};
			jwt.sign(
				payload,
				process.env.jwtSecret,
				{
					expiresIn: 36000,
				},
				(err, token) => {
					if (err) throw err;
					res.json({ token });
				}
			);
		} catch (err) {
			console.error(err.message);
			res.status(500).send("Server Error");
		}
	}
);

module.exports = router;
