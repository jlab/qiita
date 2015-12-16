# -----------------------------------------------------------------------------
# Copyright (c) 2014--, The Qiita Development Team.
#
# Distributed under the terms of the BSD 3-clause License.
#
# The full license is in the file LICENSE, distributed with this software.
# -----------------------------------------------------------------------------
from __future__ import division

from tornado.web import authenticated, HTTPError
# This is the only file in qiita_pet that should import from outside qiita_pet
# The idea is that this proxies the call and response dicts we expect from the
# Qiita API once we build it. This will be removed and replaced with API calls
# when the API is complete.
from qiita_core.qiita_settings import qiita_config
from qiita_db.study import Study
from qiita_db.metadata_template.prep_template import PrepTemplate
from qiita_db.artifact import Artifact

from qiita_pet.handlers.base_handlers import BaseHandler
from qiita_pet.handlers.util import check_access

html_error_message = "<b>An error occurred %s %s</b></br>%s"


def _approve(level):
    """Check if the study can be approved based on user level and configuration

    Parameters
    ----------
    level : str
        The level of the current user

    Returns
    -------
    bool
        Whether the study can be approved or not
    """
    return True if not qiita_config.require_approval else level == 'admin'


class StudyAPIProxy(BaseHandler):
    """Adds API proxy functions to the handler. Can be removed once the RESTful
       API is in place."""
    @authenticated
    def study_prep_proxy(self, study_id):
        """Proxies expected json from the API for existing prep templates

        Parameters
        ----------
        study_id : int
            Study id to get prep template info for

        Returns
        -------
        dict of list of dict
            prep template information seperated by data type, in the form
            {data_type: [{prep 1 info dict}, ....], ...}

        Raises
        ------
        HTTPError
            Raises code 403 if user does not have access to the study
        """
        # Can only pass ids over API, so need to instantiate object
        study = Study(study_id)
        check_access(self.current_user, study, raise_error=True)
        full_access = study.has_access(self.current_user, no_public=True)
        prep_info = {}
        for dtype in study.data_types:
            prep_info[dtype] = []
            for prep in study.prep_templates(dtype):
                if not full_access and prep.status != 'public':
                    continue
                start_artifact = prep.artifact
                info = {
                    'name': 'PREP %d NAME' % prep.id,
                    'id': prep.id,
                    'status': prep.status,
                    'start_artifact': start_artifact.artifact_type,
                    'start_artifact_id': start_artifact.id,
                    'last_artifact': 'TODO new gui'
                }
                prep_info[dtype].append(info)
        return prep_info

    @authenticated
    def prep_graph_proxy(self, prep_id):
        """Proxies expected API output for getting file creation DAG

        Parameters
        ----------
        prep_id : int
            Prep template ID to get graph for

        Returns
        -------
        dict of lists of tuples
            A dictionary containing the edge list representation of the graph,
            and the node labels. Formatted as:
            {'edge_list': [(0, 1), (0, 2)...],
             'node_labels': [(0, 'label0'), (1, 'label1'), ...]}

        Raises
        ------
        HTTPError
            Raises code 400 if unknown direction passed

        Notes
        -----
        Nodes are identified by the corresponding Artifact ID.
        """
        G = PrepTemplate(int(prep_id)).artifact.descendants

        node_labels = [(n.id, 'longer descriptive name for %d' % n.id)
                       for n in G.nodes()]
        return {'edge_list': [(n.id, m.id) for n, m in G.edges()],
                'node_labels': node_labels}

    @authenticated
    def artifact_graph_proxy(self, artifact_id, direction):
        """Proxies expected API output for getting file creation DAG

        Parameters
        ----------
        artifact_id : int
            Artifact ID to get graph for
        direction : {'ancestors', 'descendants'}
            What direction to get the graph in

        Returns
        -------
        dict of lists of tuples
            A dictionary containing the edge list representation of the graph,
            and the node labels. Formatted as:
            {'edge_list': [(0, 1), (0, 2)...],
             'node_labels': [(0, 'label0'), (1, 'label1'), ...]}

        Raises
        ------
        HTTPError
            Raises code 400 if unknown direction passed

        Notes
        -----
        Nodes are identified by the corresponding Artifact ID.
        """
        if direction == 'descendants':
            G = Artifact(int(artifact_id)).descendants
        elif direction == 'ancestors':
            G = Artifact(int(artifact_id)).ancestors
        else:
            raise HTTPError(400, 'Unknown direction %s' % direction)

        node_labels = [(n.id, 'longer descriptive name for %d' % n.id)
                       for n in G.nodes()]
        return {'edge_list': [(n.id, m.id) for n, m in G.edges()],
                'node_labels': node_labels}

    @authenticated
    def study_data_types_proxy(self):
        """Proxies expected json from the API for available data types

        Returns
        -------
        list of str
            Data types available on the system
        """
        data_types = Study.all_data_types()
        return data_types

    @authenticated
    def study_info_proxy(self, study_id):
        """Proxies expected json from the API for base study info

        Parameters
        ----------
        study_id : int
            Study id to get prep template info for

        Returns
        -------
        dict of list of dict
            prep template information seperated by data type, in the form
            {data_type: [{prep 1 info dict}, ....], ...}

        Raises
        ------
        HTTPError
            Raises code 403 if user does not have access to the study
        """
        # Can only pass ids over API, so need to instantiate object
        study = Study(study_id)
        check_access(self.current_user, study, raise_error=True)
        study_info = study.info
        # Add needed info that is not part of the initial info pull
        study_info['publications'] = study.publications
        study_info['study_id'] = study.id
        study_info['study_title'] = study.title
        study_info['shared_with'] = [s.id for s in study.shared_with]
        study_info['status'] = study.status

        # Clean up StudyPerson objects to string for display
        pi = study_info["principal_investigator"]
        study_info["principal_investigator"] = {
            'name': pi.name,
            'email': pi.email,
            'affiliation': pi.affiliation
        }
        lab_person = study_info["lab_person"]
        study_info["lab_person"] = {
            'name': lab_person.name,
            'email': lab_person.email,
            'affiliation': lab_person.affiliation
        }

        samples = study.sample_template.keys()
        study_info['num_samples'] = 0 if samples is None else len(set(samples))
        return study_info
