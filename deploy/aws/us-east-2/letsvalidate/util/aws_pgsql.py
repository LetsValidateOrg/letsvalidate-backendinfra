import letsvalidate.util.aws_ssm
import psycopg


def _get_ssm_db_parameters():

    param_store_keys = (
        "/letsvalidate/db/aws/us-east-2/dbname",
        "/letsvalidate/db/aws/us-east-2/dbhost",
        "/letsvalidate/db/aws/us-east-2/dbuser",
        "/letsvalidate/db/aws/us-east-2/dbpassword",
    )

    return letsvalidate.util.aws_ssm.get_ssm_params( param_store_keys )


def get_db_handle():
    db_params = _get_ssm_db_parameters()
    #logger.debug("DB params:")
    #logger.debug(json.dumps(db_params, indent=4, sort_keys=True))

    return psycopg.connect(
        host        = db_params['dbhost'],
        user        = db_params['dbuser'],
        password    = db_params['dbpassword'],
        dbname      = db_params['dbname'] )

