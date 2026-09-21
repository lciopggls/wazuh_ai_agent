import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../src/views/index/index.vue", import.meta.url),
  "utf8",
);

test("页面和侧边栏切换不会卸载正在流式响应的聊天组件", () => {
  assert.match(
    source,
    /<div v-show="currentPage === 2" class="second-page-box">/,
  );
  assert.match(
    source,
    /<div v-show="currentMenu === 'ai-chat'" class="persistent-chat-view">\s+<second_right\s+key="production-chat"/,
  );
  assert.doesNotMatch(
    source,
    /<template v-(?:if|else-if)="currentMenu === 'ai-chat'/,
  );
});
