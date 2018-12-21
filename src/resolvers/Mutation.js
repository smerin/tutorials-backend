const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
// const { randomBytes } = require("crypto");
// const { promisify } = require("util");
// const { transport, makeANiceEmail } = require("../mail");

const Mutations = {
  async signup(parent, args, ctx, info) {
    // lowercase their email
    args.email = args.email.toLowerCase();
    // hash their password
    const password = await bcrypt.hash(args.password, 10);
    // create the user in the database
    const user = await ctx.db.mutation.createUser(
      {
        data: {
          ...args,
          password,
          permissions: { set: ["USER"] }
        }
      },
      info
    );
    // create the JWT token for them
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // set the jwt as a cookie on the response
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    });
    // Finallllly we return the user to the browser
    return user;
  },
  async signin(parent, { email, password }, ctx, info) {
    // 1. Check if there is a user with that email
    const user = await ctx.db.query.user({ where: { email } });
    if (!user) {
      throw new Error(`No user found for email ${email}`);
    }
    // 2. Check if their password is correct
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error("Invalid password!");
    }
    // 3. Generate the JWT token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // 4. Set the cookie with the token
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
    // 5. Return the user
    return user;
  },
  async signout(parent, args, ctx, info) {
    ctx.response.clearCookie("token");
    return { message: "Signed out successfully!" };
  },
  async createLesson(parent, args, ctx, info) {
    // 1. Check if user is logged in
    const { userId } = ctx.request;
    if (!userId) throw new Error("You must be logged in to do this");

    // 2. TODO: Check user has permissions to create a tutorial
    // TODO

    // 3. Create the lesson
    return ctx.db.mutation.createLesson(
      {
        data: {
          user: { connect: { id: userId } },
          ...args
        }
      },
      info
    );
  }
};

module.exports = Mutations;
