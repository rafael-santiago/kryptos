git clone https://github.com/rafael-santiago/hefesto --recursive
cd hefesto/src
copy ..\..\src\build\ci\windows\build.bat . /Y
printf "\n" > blau.txt
build.bat < blau.txt
cd ../..
del /s /q hefesto
