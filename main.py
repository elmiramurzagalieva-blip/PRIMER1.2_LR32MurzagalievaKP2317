# пункт 1 - создан 1 секретный ключ

# пункт 2 - вариант 53
#Микросервис фильрации и проверки контейнера для обеспечения информационной безопасности приложения при угрозе внедрения вредоносного кода через рекламу, сервис и контент
import re
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from collections import defaultdict

# Конфигурация правил фильтрации
BLACKLIST = ["bit.ly/3x", "fake-update.site", "malware.ru", "shortlink-danger.ru"]
PATTERNS = [r"<script>", r"eval\(", r"iframe", r"window\.location", r"document\.write"]
RISK_SRC = {"ad": 25, "service": 10, "content": 0}
RISK_TYPE = {"script": 40, "html": 10, "image": 0, "video": 5}
RISK_ACT = {"auto_execute": 35, "click": 20, "download": 25, "view": 0}
THRESHOLD = 70
SEVERITY = [(90, "КРИТИЧНО"), (70, "ВЫСОКИЙ"), (40, "СРЕДНИЙ"), (0, "НИЗКИЙ")]

# Входная информация контейнера
DATA = [
    {"id": "EVT-001","src": "ad","url": "https://bit.ly/3x?payload","type": "script","act": "auto_execute","time": "10:12",},
    {"id": "EVT-002","src": "content","url": "https://safe.com/img.png","type": "image","act": "view","time": "10:14",},
    {"id": "EVT-003","src": "service","url": "https://api.app.com/data","type": "html","act": "click","time": "10:15",},
    {"id": "EVT-004","src": "ad","url": "https://fake-update.site/eval(1)","type": "script","act": "download","time": "10:16",},
    {"id": "EVT-005","src": "content","url": "https://news.ru/article","type": "html","act": "view","time": "10:18",},
    {"id": "EVT-006","src": "ad","url": "https://track.ru/pixel","type": "image","act": "view","time": "10:20",},
    {"id": "EVT-007","src": "service","url": "https://malware.ru/<script>","type": "html","act": "click","time": "10:22",},
    {"id": "EVT-008","src": "ad","url": "https://bad.ru/iframe?hack","type": "script","act": "auto_execute","time": "10:25",},
    {"id": "EVT-009","src": "content","url": "https://cdn.net/video.mp4","type": "video","act": "download","time": "10:27",},
    {"id": "EVT-010","src": "service","url": "https://docs.app.com/help","type": "html","act": "view","time": "10:30",},
    {"id": "EVT-011","src": "ad","url": "https://shortlink-danger.ru/open","type": "script","act": "auto_execute","time": "10:32",},
    {"id": "EVT-012","src": "content","url": "https://legit.com/page","type": "html","act": "view","time": "10:35",},
]


# Контейнер расчета
def analyze(e):
    score, reasons = 0, []
    url = e["url"]
    for bl in BLACKLIST:
        if bl in url:
            score += 90
            reasons.append(f"BlackList: {bl}")
            break
    for pat in PATTERNS:
        if re.search(pat, url, re.I):
            score += 85
            reasons.append(f"Pattern: {pat}")
            break
    score += (
        RISK_SRC.get(e["src"], 0)
        + RISK_TYPE.get(e["type"], 0)
        + RISK_ACT.get(e["act"], 0)
    )
    score = min(score, 100)
    sev = next((lvl for thr, lvl in SEVERITY if score >= thr), "НИЗКИЙ")
    status = "ЗАБЛОКИРОВАНО" if score >= THRESHOLD else "РАЗРЕШЕНО"
    result = e.copy()
    result["score"] = score
    result["status"] = status
    result["reason"] = "; ".join(reasons) or "Чисто"
    result["severity"] = sev
    return result


def process(data):
    return [analyze(e) for e in data]


# Контейнер табличного представления
def print_console_tables(res):
    print("\nТАБЛИЦА 1 - ЖУРНАЛ ЛОГОВ")
    print(
        f"{'№':<3} {'ВРЕМЯ':<6} {'ИСТОЧНИК':<9} {'URL':<36} {'СТАТУС':<16} {'РИСК':<5} {'УРОВЕНЬ':<10} {'ПРИЧИНА'}"
    )
 
    for i, r in enumerate(res, 1):
        url_s = r["url"][:40] + ".." if len(r["url"]) > 42 else r["url"]
        print(
            f"{i:<3} {r['time']:<6} {r['src']:<9} {url_s:<36} {r['status']:<16} {r['score']:<5} {r['severity']:<10} {r['reason']}"
        )

    total, blocked = len(res), sum(1 for r in res if r["status"] == "ЗАБЛОКИРОВАНО")
    print(
        f"\nСТАТИСТИКА: Всего: {total}  РАЗРЕШЕНО: {total - blocked}  ЗАБЛОКИРОВАНО: {blocked}"
    )
    print(f"Доля блокировок: {round(blocked / total * 100, 1) if total else 0}%")

    # Таблица статистики по источникам
    print(' ')
    print("\nТАБЛИЦА 2 - СТАТИСТИКА ПО ИСТОЧНИКАМ УГРОЗ")
    print(
        f"{'Источник':<10} {'РАЗРЕШЕНО':<5} {'БЛОК':<5} {'ВСЕГО':<6} {'СР.РИСК':<9} {'НАДЕЖНОСТЬ':<8}"
    )

    for src in ["ad", "service", "content"]:
        items = [r for r in res if r["src"] == src]
        if not items:
            continue
        ok = sum(1 for r in items if r["status"] == "РАЗРЕШЕНО")
        bl = len(items) - ok
        avg = round(sum(r["score"] for r in items) / len(items), 1)
        rel = round((1 - bl / len(items)) * 100, 1)
        print(f"{src:<10} {ok:<9} {bl:<5} {len(items):<6} {avg:<9} {rel}%")

    # Таблица распределения по типам контента
    print(' ')
    print("\nТАБЛИЦА 3 - РАСПРЕДЕЛЕНИЕ ПО ТИПАМ КОНТЕНТА")
    print(f"{'ТИП':<10} {'ВСЕГО':<8} {'БЛОК':<8} {'СР.РИСК':<10}")

    for ct in ["script", "html", "image", "video"]:
        items = [r for r in res if r["type"] == ct]
        if not items:
            continue
        bl = sum(1 for r in items if r["status"] == "ЗАБЛОКИРОВАНО")
        avg = round(sum(r["score"] for r in items) / len(items), 1)
        print(f"{ct:<10} {len(items):<8} {bl:<8} {avg}")


# Контейнер визуализации
def save_charts(res):
    plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial"] #шрифты
  
    #Диаграмма по статусу
    st = {"РАЗРЕШЕНО": 0, "ЗАБЛОКИРОВАНО": 0}
    for r in res:
        st[r["status"]] += 1
    fig, ax = plt.subplots()
    ax.pie(
        st.values(), labels=st.keys(), autopct="%1.1f%%", colors=["#BDB76B", "#F08080"]
    )
    ax.set_title("Решения микросервиса")
    fig.savefig("status_chart.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
  
    #Диаграмма по источникам
    fig, ax = plt.subplots()
    src_stats = defaultdict(lambda: {"total": 0, "blocked": 0})
    for r in res:
        src_stats[r["src"]]["total"] += 1
    for r in res:
        if r["status"] == "ЗАБЛОКИРОВАНО":
            src_stats[r["src"]]["blocked"] += 1
    keys = list(src_stats.keys())
    ax.bar(
        keys, [v["blocked"] for v in src_stats.values()], color="#9370DB", label="Блок"
    )
    ax.bar(
        keys,
        [v["total"] - v["blocked"] for v in src_stats.values()],
        bottom=[v["blocked"] for v in src_stats.values()],
        color="#48D1CC",
        label="Разрешено",
    )
    ax.set_title("Фильтрация по источникам")
    ax.set_ylabel("События")
    ax.legend()
    fig.tight_layout()
    fig.savefig("source_chart.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
  
    #Диаграмма по уровню риска
    fig, ax = plt.subplots()
    colors = ["#FF7F50" if r["score"] >= THRESHOLD else "#6495ED" for r in res]
    ax.bar([r["id"] for r in res], [r["score"] for r in res], color=colors)
    ax.axhline(y=THRESHOLD, color="red", linestyle="--", label="Порог") #линия порога
    ax.set_title("Уровень риска")
    ax.set_ylabel("Величина риска")
    plt.xticks(rotation=45, ha="right")
    ax.legend()
    fig.tight_layout()
    fig.savefig("risk_chart.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


# Запуск
def main():
    print("КОНТЕЙНЕР ЗАЩИТЫ ОТ ВНЕДРЕНИЯ КОДА ЧЕРЕЗ РЕКЛАМУ, СЕРВИС И КОНТЕНТ (Вариант 53)")
    results = process(DATA)
    print_console_tables(results)
    save_charts(results)


if __name__ == "__main__":
    main()


#пункт 3 - удалила контейнер визуализации и восставновила его с помощью встроенных инструментов
