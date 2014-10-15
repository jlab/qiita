r"""
Metadata template objects (:mod: `qiita_db.metadata_template)
=============================================================

..currentmodule:: qiita_db.metadata_template

This module provides the MetadataTemplate base class and the subclasses
SampleTemplate and PrepTemplate.

Classes
-------

..autosummary::
    :toctree: generated/

    BaseSample
    Sample
    PrepSample
    MetadataTemplate
    SampleTemplate
    PrepTemplate

Methods
-------

..autosummary::
    :toctree: generated/

    sample_template_adder
"""

# -----------------------------------------------------------------------------
# Copyright (c) 2014--, The Qiita Development Team.
#
# Distributed under the terms of the BSD 3-clause License.
#
# The full license is in the file LICENSE, distributed with this software.
# -----------------------------------------------------------------------------

from __future__ import division
from future.builtins import zip
from future.utils import viewitems
from copy import deepcopy

import pandas as pd
import numpy as np

from qiita_core.exceptions import IncompetentQiitaDeveloperError
from .exceptions import (QiitaDBDuplicateError, QiitaDBColumnError,
                         QiitaDBUnknownIDError, QiitaDBNotImplementedError,
                         QiitaDBDuplicateHeaderError)
from .base import QiitaObject
from .sql_connection import SQLConnectionHandler
from .util import (exists_table, get_table_cols, get_emp_status,
                   get_required_sample_info_status)


TARGET_GENE_DATA_TYPES = ['16S', '18S', 'ITS']
REQUIRED_TARGET_GENE_COLS = {'barcodesequence', 'linkerprimersequence'}
RENAME_COLS_DICT = {'barcode': 'barcodesequence',
                    'primer': 'linkerprimersequence'}


def _get_datatypes(metadata_map):
    r"""Returns the datatype of each metadata_map column

    Parameters
    ----------
    metadata_map : DataFrame
        The MetadataTemplate contents

    Returns
    -------
    list of str
        The SQL datatypes for each column, in column order
    """
    datatypes = []
    for dtype in metadata_map.dtypes:
        if dtype in [np.int8, np.int16, np.int32, np.int64]:
            datatypes.append('integer')
        elif dtype in [np.float16, np.float32, np.float64]:
            datatypes.append('float8')
        else:
            datatypes.append('varchar')
    return datatypes


def _as_python_types(metadata_map, headers):
    r"""Converts the values of metadata_map pointed by headers from numpy types
    to python types.

    Psycopg2 does not support the numpy types, so we should cast them to the
    closest python type

    Parameters
    ----------
    metadata_map : DataFrame
        The MetadataTemplate contents
    headers : list of str
        The headers of the columns of metadata_map that needs to be converted
        to a python type

    Returns
    -------
    list of lists
        The values of the columns in metadata_map pointed by headers casted to
        python types.
    """
    values = []
    for h in headers:
        if isinstance(metadata_map[h][0], np.generic):
            values.append(list(map(np.asscalar, metadata_map[h])))
        else:
            values.append(list(metadata_map[h]))
    return values


class BaseSample(QiitaObject):
    r"""Sample object that accesses the db to get the information of a sample
    belonging to a PrepTemplate or a SampleTemplate.

    Parameters
    ----------
    sample_id : str
        The sample id
    md_template : MetadataTemplate
        The metadata template obj to which the sample belongs to

    Methods
    -------
    __eq__
    __len__
    __getitem__
    __setitem__
    __delitem__
    __iter__
    __contains__
    exists
    keys
    values
    items
    get

    See Also
    --------
    QiitaObject
    Sample
    PrepSample
    """
    # Used to find the right SQL tables - should be defined on the subclasses
    _table_prefix = None
    _column_table = None
    _id_column = None

    def _check_template_class(self, md_template):
        r"""Checks that md_template is of the correct type

        Parameters
        ----------
        md_template : MetadataTemplate
            The metadata template

        Raises
        ------
        IncompetentQiitaDeveloperError
            If its call directly from the Base class
            If `md_template` doesn't have the correct type
        """
        raise IncompetentQiitaDeveloperError()

    def __init__(self, sample_id, md_template):
        r"""Initializes the object

        Parameters
        ----------
        sample_id : str
            The sample id
        md_template : MetadataTemplate
            The metadata template in which the sample is present

        Raises
        ------
        QiitaDBUnknownIDError
            If `sample_id` does not correspond to any sample in md_template
        """
        # Check that we are not instantiating the base class
        self._check_subclass()
        # Check that the md_template is of the correct type
        self._check_template_class(md_template)
        # Check if the sample id is present on the passed metadata template
        # This test will check that the sample id is actually present on the db
        if sample_id not in md_template:
            raise QiitaDBUnknownIDError(sample_id, self.__class__.__name__)
        # Assign private attributes
        self._id = sample_id
        self._md_template = md_template
        self._dynamic_table = "%s%d" % (self._table_prefix,
                                        self._md_template.id)

    def __hash__(self):
        r"""Defines the hash function so samples are hashable"""
        return hash(self._id)

    def __eq__(self, other):
        r"""Self and other are equal based on type and ids"""
        if not isinstance(other, type(self)):
            return False
        if other._id != self._id:
            return False
        if other._md_template != self._md_template:
            return False
        return True

    @classmethod
    def exists(cls, sample_id, md_template):
        r"""Checks if already exists a MetadataTemplate for the provided object

        Parameters
        ----------
        sample_id : str
            The sample id
        md_template : MetadataTemplate
            The metadata template to which the sample belongs to

        Returns
        -------
        bool
            True if already exists. False otherwise.
        """
        cls._check_subclass()
        conn_handler = SQLConnectionHandler()
        return conn_handler.execute_fetchone(
            "SELECT EXISTS(SELECT * FROM qiita.{0} WHERE sample_id=%s AND "
            "{1}=%s)".format(cls._table, cls._id_column),
            (sample_id, md_template.id))[0]

    def _get_categories(self, conn_handler):
        r"""Returns all the available metadata categories for the sample

        Parameters
        ----------
        conn_handler : SQLConnectionHandler
            The connection handler object connected to the DB

        Returns
        -------
        set of str
            The set of all available metadata categories
        """
        # Get all the required columns
        required_cols = get_table_cols(self._table, conn_handler)
        # Get all the the columns in the dynamic table
        dynamic_cols = get_table_cols(self._dynamic_table, conn_handler)
        # Get the union of the two previous lists
        cols = set(required_cols).union(dynamic_cols)
        # Remove the sample_id column and the study_id/raw_data_id columns,
        # as this columns are used internally for data storage and they don't
        # actually belong to the metadata
        cols.remove('sample_id')
        cols.remove(self._id_column)
        # Change the *_id columns, as this is for convenience internally,
        # and add the original categories
        for key, value in viewitems(self._md_template.translate_cols_dict):
            cols.remove(key)
            cols.add(value)

        return cols

    def _to_dict(self):
        r"""Returns the categories and their values in a dictionary

        Returns
        -------
        dict of {str: str}
            A dictionary of the form {category: value}
        """
        conn_handler = SQLConnectionHandler()
        d = dict(conn_handler.execute_fetchone(
            "SELECT * FROM qiita.{0} WHERE {1}=%s AND "
            "sample_id=%s".format(self._table, self._id_column),
            (self._md_template.id, self._id)))
        dynamic_d = dict(conn_handler.execute_fetchone(
            "SELECT * from qiita.{0} WHERE "
            "sample_id=%s".format(self._dynamic_table),
            (self._id, )))
        d.update(dynamic_d)
        del d['sample_id']
        del d[self._id_column]
        # Modify all the *_id columns to include the string instead of the id
        for k, v in viewitems(self._md_template.translate_cols_dict):
            d[v] = self._md_template.str_cols_handlers[k][d[k]]
            del d[k]
        return d

    def __len__(self):
        r"""Returns the number of metadata categories

        Returns
        -------
        int
            The number of metadata categories
        """
        conn_handler = SQLConnectionHandler()
        # return the number of columns
        return len(self._get_categories(conn_handler))

    def __getitem__(self, key):
        r"""Returns the value of the metadata category `key`

        Parameters
        ----------
        key : str
            The metadata category

        Returns
        -------
        obj
            The value of the metadata category `key`

        Raises
        ------
        KeyError
            If the metadata category `key` does not exists

        See Also
        --------
        get
        """
        conn_handler = SQLConnectionHandler()
        key = key.lower()
        if key in self._get_categories(conn_handler):
            # It's possible that the key is asking for one of the *_id columns
            # that we have to do the translation
            handler = lambda x: x
            if key in self._md_template.translate_cols_dict.values():
                handler = (
                    lambda x: self._md_template.str_cols_handlers[key][x])
                key = "%s_id" % key
            # Check if we have either to query the table with required columns
            # or the dynamic table
            if key in get_table_cols(self._table, conn_handler):
                result = conn_handler.execute_fetchone(
                    "SELECT {0} FROM qiita.{1} WHERE {2}=%s AND "
                    "sample_id=%s".format(key, self._table, self._id_column),
                    (self._md_template.id, self._id))[0]
                return handler(result)
            else:
                return conn_handler.execute_fetchone(
                    "SELECT {0} FROM qiita.{1} WHERE "
                    "sample_id=%s".format(key, self._dynamic_table),
                    (self._id, ))[0]
        else:
            # The key is not available for the sample, so raise a KeyError
            raise KeyError("Metadata category %s does not exists for sample %s"
                           " in template %d" %
                           (key, self._id, self._md_template.id))

    def __setitem__(self, key, value):
        r"""Sets the metadata value for the category `key`

        Parameters
        ----------
        key : str
            The metadata category
        value : obj
            The new value for the category
        """
        raise QiitaDBNotImplementedError()

    def __delitem__(self, key):
        r"""Removes the sample with sample id `key` from the database

        Parameters
        ----------
        key : str
            The sample id
        """
        raise QiitaDBNotImplementedError()

    def __iter__(self):
        r"""Iterator over the metadata keys

        Returns
        -------
        Iterator
            Iterator over the sample ids

        See Also
        --------
        keys
        """
        conn_handler = SQLConnectionHandler()
        return iter(self._get_categories(conn_handler))

    def __contains__(self, key):
        r"""Checks if the metadata category `key` is present

        Parameters
        ----------
        key : str
            The sample id

        Returns
        -------
        bool
            True if the metadata category `key` is present, false otherwise
        """
        conn_handler = SQLConnectionHandler()
        return key.lower() in self._get_categories(conn_handler)

    def keys(self):
        r"""Iterator over the metadata categories

        Returns
        -------
        Iterator
            Iterator over the sample ids

        See Also
        --------
        __iter__
        """
        return self.__iter__()

    def values(self):
        r"""Iterator over the metadata values, in metadata category order

        Returns
        -------
        Iterator
            Iterator over metadata values
        """
        d = self._to_dict()
        return d.values()

    def items(self):
        r"""Iterator over (category, value) tuples

        Returns
        -------
        Iterator
            Iterator over (category, value) tuples
        """
        d = self._to_dict()
        return d.items()

    def get(self, key):
        r"""Returns the metadata value for category `key`, or None if the
        category `key` is not present

        Parameters
        ----------
        key : str
            The metadata category

        Returns
        -------
        Obj or None
            The value object for the category `key`, or None if it is not
            present

        See Also
        --------
        __getitem__
        """
        try:
            return self[key]
        except KeyError:
            return None


class PrepSample(BaseSample):
    r"""Class that models a sample present in a PrepTemplate.

    See Also
    --------
    BaseSample
    Sample
    """
    _table = "common_prep_info"
    _table_prefix = "prep_"
    _column_table = "raw_data_prep_columns"
    _id_column = "raw_data_id"

    def _check_template_class(self, md_template):
        r"""Checks that md_template is of the correct type

        Parameters
        ----------
        md_template : PrepTemplate
            The metadata template

        Raises
        ------
        IncompetentQiitaDeveloperError
            If `md_template` is not a PrepTemplate object
        """
        if not isinstance(md_template, PrepTemplate):
            raise IncompetentQiitaDeveloperError()


class Sample(BaseSample):
    r"""Class that models a sample present in a SampleTemplate.

    See Also
    --------
    BaseSample
    PrepSample
    """
    _table = "required_sample_info"
    _table_prefix = "sample_"
    _column_table = "study_sample_columns"
    _id_column = "study_id"

    def _check_template_class(self, md_template):
        r"""Checks that md_template is of the correct type

        Parameters
        ----------
        md_template : SampleTemplate
            The metadata template

        Raises
        ------
        IncompetentQiitaDeveloperError
            If `md_template` is not a SampleTemplate object
        """
        if not isinstance(md_template, SampleTemplate):
            raise IncompetentQiitaDeveloperError()


class MetadataTemplate(QiitaObject):
    r"""Metadata map object that accesses the db to get the sample/prep
    template information

    Attributes
    ----------
    id

    Methods
    -------
    create
    exists
    __len__
    __getitem__
    __setitem__
    __delitem__
    __iter__
    __contains__
    keys
    values
    items
    get
    to_file

    See Also
    --------
    QiitaObject
    SampleTemplate
    PrepTemplate
    """

    # Used to find the right SQL tables - should be defined on the subclasses
    _table_prefix = None
    _column_table = None
    _id_column = None
    _strict = True
    _sample_cls = None

    def _check_id(self, id_, conn_handler=None):
        r"""Checks that the MetadataTemplate id_ exists on the database"""
        self._check_subclass()
        conn_handler = (conn_handler if conn_handler is not None
                        else SQLConnectionHandler())
        return conn_handler.execute_fetchone(
            "SELECT EXISTS(SELECT * FROM qiita.{0} WHERE "
            "{1}=%s)".format(self._table, self._id_column),
            (id_, ))[0]

    @classmethod
    def _table_name(cls, obj):
        r"""Returns the dynamic table name

        Parameters
        ----------
        obj : Study or RawData
            The obj to which the metadata template belongs to.

        Returns
        -------
        str
            The table name

        Raises
        ------
        IncompetentQiitaDeveloperError
            If called from the base class directly
        """
        if not cls._table_prefix:
            raise IncompetentQiitaDeveloperError(
                "_table_prefix should be defined in the subclasses")
        return "%s%d" % (cls._table_prefix, obj.id)

    @classmethod
    def _check_special_columns(cls, md_template, obj):
        r"""Checks for special columns based on obj type

        Parameters
        ----------
        md_template : DataFrame
            The metadata template file contents indexed by sample ids
        obj : Study or RawData
            The obj to which the metadata template belongs to. Study in case
            of SampleTemplate and RawData in case of PrepTemplate
        """
        # Check required columns
        missing = set(cls.translate_cols_dict.values()).difference(md_template)
        if missing:
            raise QiitaDBColumnError("Missing columns: %s"
                                     % ', '.join(map(str, missing)))

        # Change any *_id column to its str column
        for key, value in viewitems(cls.translate_cols_dict):
            handler = cls.id_cols_handlers[key]
            md_template[key] = pd.Series(
                [handler[i] for i in md_template[value]],
                index=md_template.index)
            del md_template[value]

        cls._check_template_special_columns(md_template, obj)

    @classmethod
    def create(cls, md_template, obj):
        r"""Creates the metadata template in the database

        Parameters
        ----------
        md_template : DataFrame
            The metadata template file contents indexed by samples Ids
        obj : Study or RawData
            The obj to which the metadata template belongs to. Study in case
            of SampleTemplate and RawData in case of PrepTemplate
        """
        cls._check_subclass()

        # Check that we don't have a MetadataTemplate for obj
        if cls.exists(obj):
            raise QiitaDBDuplicateError(cls.__name__, 'id: %d' % obj.id)

        # We are going to modify the md_template. We create a copy so
        # we don't modify the user one
        md_template = deepcopy(md_template)
        # In the database, all the column headers are lowercase
        md_template.columns = [c.lower() for c in md_template.columns]

        # Check that we don't have duplicate columns
        if len(set(md_template.columns)) != len(md_template.columns):
            raise QiitaDBDuplicateHeaderError()

        # We need to check for some special columns, that are not present on
        # the database, but depending on the data type are required.
        cls._check_special_columns(md_template, obj)

        conn_handler = SQLConnectionHandler()

        # Get some useful information from the metadata template
        sample_ids = md_template.index.tolist()
        num_samples = len(sample_ids)

        # Get the required columns from the DB
        db_cols = get_table_cols(cls._table, conn_handler)

        # Remove the sample_id and study_id columns
        db_cols.remove('sample_id')
        db_cols.remove(cls._id_column)

        # Retrieve the headers of the metadata template
        headers = list(md_template.keys())

        # Check that md_template has the required columns
        remaining = set(db_cols).difference(headers)
        if remaining:
            # If strict, raise an error, else default to None
            if cls._strict:
                raise QiitaDBColumnError("Missing columns: %s" % remaining)
            else:
                for col in remaining:
                    md_template[col] = pd.Series([None] * num_samples,
                                                 index=sample_ids)

        # Insert values on required columns
        values = _as_python_types(md_template, db_cols)
        values.insert(0, sample_ids)
        values.insert(0, [obj.id] * num_samples)
        values = [v for v in zip(*values)]
        conn_handler.executemany(
            "INSERT INTO qiita.{0} ({1}, sample_id, {2}) "
            "VALUES (%s, %s, {3})".format(cls._table, cls._id_column,
                                          ', '.join(db_cols),
                                          ', '.join(['%s'] * len(db_cols))),
            values)

        # Insert rows on *_columns table
        headers = list(set(headers).difference(db_cols))
        datatypes = _get_datatypes(md_template.ix[:, headers])
        # psycopg2 requires a list of tuples, in which each tuple is a set
        # of values to use in the string formatting of the query. We have all
        # the values in different lists (but in the same order) so use zip
        # to create the list of tuples that psycopg2 requires.
        values = [v for v in zip([obj.id] * len(headers), headers, datatypes)]
        conn_handler.executemany(
            "INSERT INTO qiita.{0} ({1}, column_name, column_type) "
            "VALUES (%s, %s, %s)".format(cls._column_table, cls._id_column),
            values)

        # Create table with custom columns
        table_name = cls._table_name(obj)
        column_datatype = ["%s %s" % (col, dtype)
                           for col, dtype in zip(headers, datatypes)]
        conn_handler.execute(
            "CREATE TABLE qiita.{0} (sample_id varchar, {1})".format(
                table_name, ', '.join(column_datatype)))

        # Insert values on custom table
        values = _as_python_types(md_template, headers)
        values.insert(0, sample_ids)
        values = [v for v in zip(*values)]
        conn_handler.executemany(
            "INSERT INTO qiita.{0} (sample_id, {1}) "
            "VALUES (%s, {2})".format(table_name, ", ".join(headers),
                                      ', '.join(["%s"] * len(headers))),
            values)

        return cls(obj.id)

    @classmethod
    def delete(cls, id_):
        r"""Deletes the table from the database

        Parameters
        ----------
        id_ : obj
            The object identifier

        """
        table_name = "%s%d" % (cls._table_prefix, id_)
        conn_handler = SQLConnectionHandler()
        conn_handler.execute(
            "DROP TABLE qiita.{0}".format(table_name))
        conn_handler.execute(
            "DELETE FROM qiita.{0} where {1} = %s".format(cls._table,
                                                          cls._id_column),
            (id_,))
        conn_handler.execute(
            "DELETE FROM qiita.{0} where {1} = %s".format(cls._column_table,
                                                          cls._id_column),
            (id_,))

    @classmethod
    def exists(cls, obj):
        r"""Checks if already exists a MetadataTemplate for the provided object

        Parameters
        ----------
        obj : QiitaObject
            The object to test if a MetadataTemplate exists for

        Returns
        -------
        bool
            True if already exists. False otherwise.
        """
        cls._check_subclass()
        return exists_table(cls._table_name(obj), SQLConnectionHandler())

    def _get_sample_ids(self, conn_handler):
        r"""Returns all the available samples for the metadata template

        Parameters
        ----------
        conn_handler : SQLConnectionHandler
            The connection handler object connected to the DB

        Returns
        -------
        set of str
            The set of all available sample ids
        """
        sample_ids = conn_handler.execute_fetchall(
            "SELECT sample_id FROM qiita.{0} WHERE "
            "{1}=%s".format(self._table, self._id_column),
            (self._id, ))
        return set(sample_id[0] for sample_id in sample_ids)

    def __len__(self):
        r"""Returns the number of samples in the metadata template

        Returns
        -------
        int
            The number of samples in the metadata template
        """
        conn_handler = SQLConnectionHandler()
        return len(self._get_sample_ids(conn_handler))

    def __getitem__(self, key):
        r"""Returns the metadata values for sample id `key`

        Parameters
        ----------
        key : str
            The sample id

        Returns
        -------
        Sample
            The sample object for the sample id `key`

        Raises
        ------
        KeyError
            If the sample id `key` is not present in the metadata template

        See Also
        --------
        get
        """
        if key in self:
            return self._sample_cls(key, self)
        else:
            raise KeyError("Sample id %s does not exists in template %d"
                           % (key, self._id))

    def __setitem__(self, key, value):
        r"""Sets the metadata values for sample id `key`

        Parameters
        ----------
        key : str
            The sample id
        value : Sample
            The sample obj holding the new sample values
        """
        raise QiitaDBNotImplementedError()

    def __delitem__(self, key):
        r"""Removes the sample with sample id `key` from the database

        Parameters
        ----------
        key : str
            The sample id
        """
        raise QiitaDBNotImplementedError()

    def __iter__(self):
        r"""Iterator over the sample ids

        Returns
        -------
        Iterator
            Iterator over the sample ids

        See Also
        --------
        keys
        """
        conn_handler = SQLConnectionHandler()
        return iter(self._get_sample_ids(conn_handler))

    def __contains__(self, key):
        r"""Checks if the sample id `key` is present in the metadata template

        Parameters
        ----------
        key : str
            The sample id

        Returns
        -------
        bool
            True if the sample id `key` is in the metadata template, false
            otherwise
        """
        conn_handler = SQLConnectionHandler()
        return key in self._get_sample_ids(conn_handler)

    def keys(self):
        r"""Iterator over the sorted sample ids

        Returns
        -------
        Iterator
            Iterator over the sample ids

        See Also
        --------
        __iter__
        """
        return self.__iter__()

    def values(self):
        r"""Iterator over the metadata values

        Returns
        -------
        Iterator
            Iterator over Sample obj
        """
        conn_handler = SQLConnectionHandler()
        return iter(self._sample_cls(sample_id, self)
                    for sample_id in self._get_sample_ids(conn_handler))

    def items(self):
        r"""Iterator over (sample_id, values) tuples, in sample id order

        Returns
        -------
        Iterator
            Iterator over (sample_ids, values) tuples
        """
        conn_handler = SQLConnectionHandler()
        return iter((sample_id, self._sample_cls(sample_id, self))
                    for sample_id in self._get_sample_ids(conn_handler))

    def get(self, key):
        r"""Returns the metadata values for sample id `key`, or None if the
        sample id `key` is not present in the metadata map

        Parameters
        ----------
        key : str
            The sample id

        Returns
        -------
        Sample or None
            The sample object for the sample id `key`, or None if it is not
            present

        See Also
        --------
        __getitem__
        """
        try:
            return self[key]
        except KeyError:
            return None

    def _transform_to_dict(self, values):
        r"""Transforms `values` to a dict keyed by sample id

        Parameters
        ----------
        values : object
            The object returned from a execute_fetchall call

        Returns
        -------
        dict
        """
        result = {}
        for row in values:
            # Transform the row to a dictionary
            values_dict = dict(row)
            # Get the sample id of this row
            sid = values_dict['sample_id']
            del values_dict['sample_id']
            # Remove _id_column from this row (if present)
            if self._id_column in values_dict:
                del values_dict[self._id_column]
            result[sid] = values_dict

        return result

    def to_file(self, fp):
        r"""Writes the MetadataTemplate to the file `fp` in tab-delimited
        format

        Parameters
        ----------
        fp : str
            Path to the output file
        """
        conn_handler = SQLConnectionHandler()
        metadata_map = self._transform_to_dict(conn_handler.execute_fetchall(
            "SELECT * FROM qiita.{0} WHERE {1}=%s".format(self._table,
                                                          self._id_column),
            (self.id,)))
        dyn_vals = self._transform_to_dict(conn_handler.execute_fetchall(
            "SELECT * FROM qiita.{0}".format(self._table_name(self))))

        for k in metadata_map:
            for key, value in viewitems(self.translate_cols_dict):
                id_ = metadata_map[k][key]
                metadata_map[k][value] = self.str_cols_handlers[key][id_]
                del metadata_map[k][key]
            metadata_map[k].update(dyn_vals[k])

        headers = sorted(list(metadata_map.values())[0].keys())
        with open(fp, 'w') as f:
            # First write the headers
            f.write("sample_name\t%s\n" % '\t'.join(headers))
            # Write the values for each sample id
            for sid, d in sorted(metadata_map.items()):
                values = [str(d[h]) for h in headers]
                values.insert(0, sid)
                f.write("%s\n" % '\t'.join(values))


class SampleTemplate(MetadataTemplate):
    r"""Represent the SampleTemplate of a study. Provides access to the
    tables in the DB that holds the sample metadata information.

    See Also
    --------
    MetadataTemplate
    PrepTemplate
    """
    _table = "required_sample_info"
    _table_prefix = "sample_"
    _column_table = "study_sample_columns"
    _id_column = "study_id"
    translate_cols_dict = {
        'required_sample_info_status_id': 'required_sample_info_status'}
    id_cols_handlers = {
        'required_sample_info_status_id': get_required_sample_info_status()}
    str_cols_handlers = {
        'required_sample_info_status_id': get_required_sample_info_status(
            key='required_sample_info_status_id')}
    _sample_cls = Sample

    @staticmethod
    def metadata_headers():
        """Returns metadata headers available

        Returns
        -------
        list
            Alphabetical list of all metadata headers available
        """
        conn_handler = SQLConnectionHandler()
        return [x[0] for x in
                conn_handler.execute_fetchall(
                "SELECT DISTINCT column_name FROM qiita.study_sample_columns "
                "UNION SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'required_sample_info' "
                "ORDER BY column_name")]

    @classmethod
    def _check_template_special_columns(cls, md_template, study):
        r"""Checks for special columns based on obj type

        Parameters
        ----------
        md_template : DataFrame
            The metadata template file contents indexed by sample ids
        study : Study
            The study to which the sample template belongs to.
        """
        pass


class PrepTemplate(MetadataTemplate):
    r"""Represent the PrepTemplate of a raw dat. Provides access to the
    tables in the DB that holds the sample preparation information.

    See Also
    --------
    MetadataTemplate
    SampleTemplate
    """
    _table = "common_prep_info"
    _table_prefix = "prep_"
    _column_table = "raw_data_prep_columns"
    _id_column = "raw_data_id"
    _strict = False
    translate_cols_dict = {'emp_status_id': 'emp_status'}
    id_cols_handlers = {'emp_status_id': get_emp_status()}
    str_cols_handlers = {'emp_status_id': get_emp_status(key='emp_status_id')}
    _sample_cls = PrepSample

    @classmethod
    def _check_template_special_columns(cls, md_template, raw_data):
        r"""Checks for special columns based on obj type

        Parameters
        ----------
        md_template : DataFrame
            The metadata template file contents indexed by sample ids
        raw_data : RawData
            The raw_data to which the prep template belongs to.

        Raises
        ------
        QiitaDBColumnError
            If any of the required columns are not present in the md_template

        Notes
        -----
        Sometimes people use different names for the same columns. We just
        rename them to use the naming that we expect, so this is normalized
        across studies.
        """
        # We only have column requirements if the data type of the raw data
        # is one of the target gene types
        if raw_data.data_type() in TARGET_GENE_DATA_TYPES:
            md_template.rename(columns=RENAME_COLS_DICT, inplace=True)

            # Check for all required columns for target genes studies
            missing_cols = REQUIRED_TARGET_GENE_COLS.difference(
                md_template.columns)
            if missing_cols:
                raise QiitaDBColumnError(
                    "The following columns are missing in the PrepTemplate and"
                    " they are requried for target gene studies: %s"
                    % missing_cols)
