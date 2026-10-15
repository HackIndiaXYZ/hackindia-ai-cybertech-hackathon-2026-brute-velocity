{ pkgs }: {
  deps = [
    pkgs.python311
    pkgs.python311Packages.pip
    pkgs.nodejs
    pkgs.git
    pkgs.zip
    pkgs.unzip
  ];
}
