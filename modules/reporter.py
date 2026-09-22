import json


def salvar_resultado(
    resultado,
    arquivo="resultado.json"
):

    with open(
        arquivo,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            resultado,
            f,
            indent=4,
            ensure_ascii=False
        )