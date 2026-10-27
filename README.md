# Deplite Run

GitHub Actions에서 이름으로 Deplite 워크플로우를 실행합니다.

```yaml
- uses: Deplite/run-action@v0
  with:
    api-token: ${{ secrets.DEPLITE_API_TOKEN }}
    agent: production-device
    workflow: deploy
    params: '{"version":"1.2.3"}'
```

더 자세한 내용은 [Deplite 문서](https://docs.deplite.io)를 참고해주세요.

## 라이선스

[Apache-2.0](LICENSE) 라이선스로 제공됩니다.
