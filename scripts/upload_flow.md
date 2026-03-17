python3 -m twine upload -r testpypi ton/dist/* jetton/dist/* wallet/dist/* dedust/dist/* nft/dist/*
# test install:
pip install -i https://test.pypi.org/simple "agton[all]"
# when satisfied:
python3 -m twine upload ton/dist/* jetton/dist/* wallet/dist/* dedust/dist/* nft/dist/*