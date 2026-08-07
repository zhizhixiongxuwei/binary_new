const encoder = new TextEncoder()

export interface PasswordChangeValues {
  currentPassword: string
  newPassword: string
  confirmation: string
}

export interface PasswordChangeErrors {
  currentPassword?: string
  newPassword?: string
  confirmation?: string
}

export function validatePasswordChange(values: PasswordChangeValues): PasswordChangeErrors {
  const errors: PasswordChangeErrors = {}

  if (!values.currentPassword) {
    errors.currentPassword = '请输入当前密码'
  }
  if (!values.newPassword) {
    errors.newPassword = '请输入新密码'
  } else if (encoder.encode(values.newPassword).byteLength < 12) {
    errors.newPassword = '新密码不能少于 12 字节'
  } else if (values.newPassword === values.currentPassword) {
    errors.newPassword = '新密码不能与当前密码相同'
  }
  if (!values.confirmation) {
    errors.confirmation = '请再次输入新密码'
  } else if (values.confirmation !== values.newPassword) {
    errors.confirmation = '两次输入的新密码不一致'
  }

  return errors
}
