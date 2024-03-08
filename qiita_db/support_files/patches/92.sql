-- Mar 8, 2024
-- The new artifact type "wordcloud" stores a PNG, a SVG, the f-scores as csv
--    and some stats about the dbBact database and query. We therefore require
--    new filepath_types, namely 'image_bitmap', 'image_vector' and
--    'tabular_plain' as definded in the qp-dbbact/qtp_wordcloud/__init__.py
--    artifact definition
INSERT INTO qiita.filepath_type (filepath_type) VALUES ('image_bitmap'), ('image_vector'), ('tabular_text');
