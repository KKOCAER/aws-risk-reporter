import pandas as pd


def export_to_csv(rows, output_path: str):
    df = pd.DataFrame(rows)
    df.to_csv(output_path, index=False)
