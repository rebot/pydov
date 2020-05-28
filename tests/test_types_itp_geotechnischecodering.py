"""Module grouping tests for the
pydov.types.interpretaties.GeotechnischeCodering class."""
from pydov.types.interpretaties import GeotechnischeCodering
from pydov.util.dovutil import build_dov_url
from tests.abstract import AbstractTestTypes

location_wfs_getfeature = \
    'tests/data/types/interpretaties/geotechnische_codering/' \
    'wfsgetfeature.xml'
location_wfs_feature = \
    'tests/data/types/interpretaties/geotechnische_codering/feature.xml'
location_dov_xml = \
    'tests/data/types/interpretaties/geotechnische_codering' \
    '/geotechnische_codering.xml'


class TestGeotechnischeCodering(AbstractTestTypes):
    """Class grouping tests for the
    pydov.types.interpretaties.GeotechnischeCodering class."""
    def get_type(self):
        """Get the class reference for this datatype.

        Returns
        -------
        pydov.types.interpretatie.GeotechnischeCodering
            Class reference for the GeotechnischeCodering class.

        """
        return GeotechnischeCodering

    def get_namespace(self):
        """Get the WFS namespace associated with this datatype.

        Returns
        -------
        str
            WFS namespace for this type.

        """
        return 'http://dov.vlaanderen.be/ocdov/interpretaties'

    def get_pkey_base(self):
        """Get the base URL for the permanent keys of this datatype.

        Returns
        -------
        str
            Base URL for the permanent keys of this datatype. For example
            "https://www.dov.vlaanderen.be/data/boring/"

        """
        return build_dov_url('data/interpretatie/')

    def get_field_names(self):
        """Get the field names for this type as listed in the documentation in
        docs/description_output_dataframes.rst

        Returns
        -------
        list
            List of field names.

        """
        return ['pkey_interpretatie', 'pkey_boring',
                'betrouwbaarheid_interpretatie', 'x', 'y',
                'diepte_laag_van', 'diepte_laag_tot',
                'hoofdnaam1_grondsoort', 'hoofdnaam2_grondsoort',
                'bijmenging1_plaatselijk', 'bijmenging1_hoeveelheid',
                'bijmenging1_grondsoort',
                'bijmenging2_plaatselijk', 'bijmenging2_hoeveelheid',
                'bijmenging2_grondsoort',
                'bijmenging3_plaatselijk', 'bijmenging3_hoeveelheid',
                'bijmenging3_grondsoort']

    def get_field_names_subtypes(self):
        """Get the field names of this type that originate from subtypes only.

        Returns
        -------
        list<str>
            List of field names from subtypes.

        """
        return ['diepte_laag_van', 'diepte_laag_tot',
                'hoofdnaam1_grondsoort', 'hoofdnaam2_grondsoort',
                'bijmenging1_plaatselijk', 'bijmenging1_hoeveelheid',
                'bijmenging1_grondsoort',
                'bijmenging2_plaatselijk', 'bijmenging2_hoeveelheid',
                'bijmenging2_grondsoort',
                'bijmenging3_plaatselijk', 'bijmenging3_hoeveelheid',
                'bijmenging3_grondsoort']

    def get_field_names_nosubtypes(self):
        """Get the field names for this type, without including fields from
        subtypes.

        Returns
        -------
        list<str>
            List of field names.

        """
        return ['pkey_interpretatie', 'pkey_boring',
                'betrouwbaarheid_interpretatie', 'x', 'y']

    def get_valid_returnfields(self):
        """Get a list of valid return fields from the main type.

        Returns
        -------
        tuple
            A tuple containing only valid return fields.

        """
        return ('pkey_interpretatie', 'pkey_boring')

    def get_valid_returnfields_subtype(self):
        """Get a list of valid return fields, including fields from a subtype.

        Returns
        -------
        tuple
            A tuple containing valid return fields, including fields from a
            subtype.

        """
        return ('pkey_interpretatie', 'diepte_laag_van', 'diepte_laag_tot')

    def get_inexistent_field(self):
        """Get the name of a field that doesn't exist.

        Returns
        -------
        str
            The name of an inexistent field.

        """
        return 'onbestaand'
