class KaggleApi:
    def authenticate(self) -> None: ...
    def dataset_download_files(
        self,
        dataset: str,
        path: str | None = ...,
        force: bool = ...,
        quiet: bool = ...,
        unzip: bool = ...,
    ) -> None: ...
    def competition_dowload_files(
        self, dataset: str, path: str | None = ..., force: bool = ..., quiet: bool = ...
    ) -> None: ...
    def competition_download_file(
        self,
        dataset: str,
        file_name: str,
        path: str | None = ...,
        force: bool | None = ...,
        quiet: bool | None = ...,
    ) -> None: ...
