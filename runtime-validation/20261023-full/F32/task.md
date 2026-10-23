# Task: pin the tested Discord dependency range

Update package metadata and the setup requirements in README.md to record the versions used by the pinned offline validation environment. It contains discord.py 2.7.1, so declare the supported tested series as `discord.py>=2.7,<2.8` and document that 2.7.1 is the validated version. Keep Python support consistent: `pyproject.toml` requires Python 3.11 or newer and README.md must continue to say Python 3.11+.

Keep the product change within exactly `pyproject.toml` and `README.md`. Do not change runtime code, tests, CI, dependencies other than the discord.py bound, or add files to the package.

Build a clean wheel and install it offline into a fresh target directory. Use the pinned `.eval-venv` and set `PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1` on every pip command. Verify the wheel metadata carries the declared Python and discord.py ranges. Do not use the network or live Discord/Orca services; do not push, publish, or merge.
