module.exports = (req, res, next) => {
    if (req.session && req.session.user) { // check object existence before checking for property {
      next()
    } else {
      res.status(401).json({message: 'You shall not pass!'})
    }
  };