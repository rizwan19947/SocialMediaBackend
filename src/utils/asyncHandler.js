/**
 * The AsyncHandler is nothing fancy
 * It's just been created as a utility to pass a request handler into
 * With this, we won't need to add Promises or try catch wrappers to
 * all of our requests.
 *
 * This is a great practice tool to keep the codebase and
 * developer experience clean and minimal, though is not
 * mandatory of course
 * @param requestHandler
 */

const asyncHandler = (requestHandler) => {
  return (req, res, next) => {
    Promise.resolve(requestHandler(req, res, next))
      .catch((error) => next(error));
  };
};


export { asyncHandler };


/**
 * Try-catch method
 */
// const asyncHandler = (fn) => async (req, res, next) => {
//   try {
//     await fn(req,res,next);
//   } catch (error) {
//       res.status(error.code || 500).json({
//         success: false,
//         message: error.message
//       })
//   }
// }