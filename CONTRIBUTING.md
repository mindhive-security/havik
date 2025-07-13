# Contributing to Havik

Thank you for considering contributing to **Havik**! We welcome contributions of all kinds — new features, bug fixes, improvements to documentation, and more.

## 📦 Setup

1. Clone the repository:

```bash
git clone https://github.com/mindhive-security/havik.git
cd havik
```

2. Install in editable mode with dependencies:

```bash
python -m pip install -e .[dev]
```

## 🧪 Code Style

Please follow these conventions:

- PEP8 with a maximum line length of 120.
- Use single quotes for strings unless double quotes are required.
- Each function and module must have a docstring.
- All functions should include type hints for arguments and return values.
- We use autopep8 for formatting. You can run it locally with:

```bash
autopep8 --in-place --recursive --aggressive --max-line-length=120 .
```

## 🧼 Before You Commit

Before submitting a PR:

- Run autopep8 to auto-format your code.
- Check that your code runs and integrates with the existing CLI (if applicable).
- Put unit tests into tests/ dicrectory and run them with pytest.
- Ensure your changes do not break existing functionality.

## 📄 Pull Requests

Create a new branch for your feature or fix.

Make sure your PR has a clear title and description.

Reference any related issues if applicable.

## 🙏 Thanks

Your contributions help **Havik** grow and improve — thank you!

If you have questions or ideas, feel free to open an issue or discussion.
