export function transformZodErrors(errors) {
  return errors.map((error) => {
    return {
      field: error.path.join('.'),
      message: error.message,
    };
  });
}
