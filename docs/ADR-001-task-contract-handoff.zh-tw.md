# ADR-001：外部、每 task 一個 authority bundle

## 狀態

已採用。

## 決定

每個 task 預設在 production repository 外建立很小的目錄：`TASK.json` 是 authority、`CONTRACT.sha256` 封存其位元組、`STATE.json` 是小型可變 snapshot、`events.jsonl` 只 append major checkpoint。

接手 Agent 必須依序驗證 contract schema/seal、project identity、authority 與 execution state。repo mismatch 一律輸出 `STOP`，不推論新任務。驗證器不選 branch、不 fast-forward、不跑測試，也不會從 repo state 讀出 task intent。

## 為何不寫進 AGENTS.md

`AGENTS.md` 是 project governance：長期、跨 task 的規則。Task Contract 是短期、特定 task 的 objective、acceptance、forbidden actions 與 progress。混在一起會增加每 session token、讓過期任務污染其他專案，並破壞責任邊界。

## 後果與限制

每次 resume 只增加兩個小檔讀取，每個 major checkpoint 只更新一個小 snapshot 加一筆 event。它不保證 task author 的內容為真，也不能防止刻意繞過流程；但能讓 authority 缺失與 repo drift 可見、可驗證、可稽核。

完整英文權威內容請見 [ADR-001-task-contract-handoff.md](ADR-001-task-contract-handoff.md)。
