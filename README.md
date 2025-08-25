# ELF Vulnerability Detector & Patcher

## 📌 Overview
This project provides a tool to **detect vulnerable functions** in ELF (`.bin`) binaries and **patch them** with safer alternatives.

✅ Detects unsafe functions (`gets`, `strcpy`, `sprintf`, …)  <br>
✅ Automatically patches with **secure wrapper functions in SAFE bin file**  <br>
✅ Supports **batch scanning** for multiple ELF files at once  <br>

<h2>[ Usage ]</h2>
You can put your several ELF(.bin) files into 'test_ELF_file' as below<br>
<br>
ex) In this picture, It's Inspecting a,b files.

![{8BE0FB80-3889-434F-80E5-4DE63CC8F0D0}](https://github.com/user-attachments/assets/b294b664-0b59-4bc7-888d-99b4bc81b93b)

![{886272DC-7803-4FB8-8703-6ACE7C11AE10}](https://github.com/user-attachments/assets/7ada1ca3-d41b-404d-8697-21bd904d2308)


<br>
<br>
and run dectection_patch.py to patch the file that could be vulnerable
<br>
<h3> > python3 detection_patch.py </h3>
<br>

<img width="791" height="31" alt="image" src="https://github.com/user-attachments/assets/e3d757f8-aaab-445b-af28-f85616efad36" />


<br>

# Result
<img width="704" height="292" alt="image" src="https://github.com/user-attachments/assets/f95668ea-79ec-4b06-940f-6be8f6116a93" />
<img width="791" height="140" alt="image" src="https://github.com/user-attachments/assets/19466884-1ff0-4fce-833a-11f29784441c" />

