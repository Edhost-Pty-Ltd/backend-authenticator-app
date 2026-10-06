export function notFoundHandler(req, res) {
  res.status(404).json({ error: 'Route not found' });
}

export function errorHandler(err, req, res, next) {
  console.error(err);

  if (res.headersSent) return next(err);

  const statusCode = Number.isInteger(err.statusCode) && err.statusCode >= 400 && err.statusCode < 600
    ? err.statusCode
    : 500;

  res.status(statusCode).json({
    error: statusCode === 500 ? 'Internal server error' : (err.message || 'Request failed'),
  });
}
