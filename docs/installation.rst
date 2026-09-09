.. highlight:: shell

============
Installation
============

Firepit supports CPython 3.11 through 3.14.

Stable release
--------------

To install firepit, run this command in your terminal:

.. code-block:: console

    $ python -m pip install firepit

This is the preferred method to install firepit, as it will install the most
recent stable release compatible with the active Python interpreter.

If you don't have `pip`_ installed, this `Python installation guide`_ can guide
you through the process.

.. _pip: https://pip.pypa.io
.. _Python installation guide: https://docs.python.org/3/installing/index.html


From sources
------------

The sources for firepit can be downloaded from the `Github repo`_.

You can clone the public repository:

.. code-block:: console

    $ git clone https://github.com/opencybersecurityalliance/firepit.git

Once you have a copy of the source, install it through the ``pyproject.toml``
build configuration:

.. code-block:: console

    $ python -m pip install .

For an editable development environment with the test, lint, documentation,
and release tools installed:

.. code-block:: console

    $ python -m pip install -e ".[test,lint,docs,release]"


.. _Github repo: https://github.com/opencybersecurityalliance/firepit
