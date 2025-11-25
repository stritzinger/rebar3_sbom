rebar3_sbom
===========

Generates a Software Bill-of-Materials (SBoM) in CycloneDX format

Use
---

Add rebar3_sbom to your rebar config, either in a project or globally in
~/.config/rebar3/rebar.config:

    {plugins, [rebar3_sbom]}.

Then run the 'sbom' task on a project:

    $ rebar3 sbom
    ===> Verifying dependencies...
    ===> CycloneDX SBoM written to bom.xml

Configuration
-------------

You can configure additional SBoM metadata in your `rebar.config`:

    {rebar3_sbom, [
        {sbom_manufacturer, #{          % Optional, all fields inside are optional
            name => "Your Organization",
            url => "https://example.com",
            address => #{
                country => "Country",
                region => "State",
                locality => "City",
                post_office_box_number => "1",
                postal_code => "12345",
                street_address => "Street Address"
            },
            contact => [
                #{name => "John Doe",
                  email => "support@example.com",
                  phone => "123456789"}
            ]
        }},
        {sbom_licenses, ["Apache-2.0"]} % Optional
    ]}.

**Note:**
- `sbom_manufacturer` (optional) identifies who is **producing the SBoM document**
  (typically your organization or CI environment), not necessarily who developed
  the software. If omitted, the manufacturer field is not included in the SBoM.
- `sbom_licenses` (optional) specifies the licenses for the **SBoM document itself**
  (the metadata), not your project. If omitted, it defaults to the same licenses
  as your project (from the `.app.src` file).
- Your project's licenses are automatically read from the `.app.src` file and
  appear in `metadata.component.licenses`.


Command Line Options
--------------------

The following command line options are supported:

    -F, --format  the file format of the SBoM output, [xml|json], [default: xml]
    -o, --output  the full path to the SBoM output file [default: ./bom.[xml|json]]
    -f, --force   overwite existing files without prompting for confirmation
                  [default: false]
    -V, --strict_version modify the version number of the BoM only when the content changes
                  [default: true]
    -a  --author  the author of the SBoM

**Author Fallback:** If `--author` is not specified, the plugin will fall back
to the `GITHUB_ACTOR` environment variable. If that variable isn't set, it will
use the authors from the project's `.app.src` file.

By default only dependencies in the 'default' profile are included. To
generate an SBoM covering development environments specify the relevant
profiles using 'as':

    $ rebar3 as default,test,docs sbom -o dev_bom.xml